package manifest

import (
	"context"
	"errors"
	"fmt"

	"github.com/docker/cli/cli/command/internal/cli"
	"github.com/docker/cli/cli/manifest/store"
	"github.com/spf13/cobra"
)

type createOpts struct {
	amend    bool
	insecure bool
}

func newCreateListCommand(dockerCli cli.Cli) *cobra.Command {
	opts := createOpts{}

	cmd := &cobra.Command{
		Use:   "create MANIFEST_LIST MANIFEST [MANIFEST...]",
		Short: "Create a local manifest list for annotating and pushing to a registry",
		Args:  cli.RequiresMinArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return createManifestList(cmd.Context(), dockerCli, args, opts)
		},
	}

	flags := cmd.Flags()
	flags.BoolVar(&opts.insecure, "insecure", false, "Allow communication with an insecure registry")
	flags.BoolVarP(&opts.amend, "amend", "a", false, "Amend an existing manifest list")
	return cmd
}

func createManifestList(ctx context.Context, dockerCLI cli.Cli, args []string, opts createOpts) error {
	newRef := args[0]
	targetRef, err := normalizeReference(newRef)
	if err != nil {
		return fmt.Errorf("error parsing name for manifest list %s: %w", newRef, err)
	}

	manifestStore := newManifestStore(dockerCLI)
	_, err = manifestStore.GetList(targetRef)
	switch {
	case store.IsNotFound(err):
		// New manifest list
	case err != nil:
		return err
	case !opts.amend:
		return errors.New("refusing to amend an existing manifest list with no --amend flag")
	}

	// Now create the local manifest list transaction by looking up the manifest schemas
	// for the constituent images:
	manifests := args[1:]
	for _, manifestRef := range manifests {
		namedRef, err := normalizeReference(manifestRef)
		if err != nil {
			// TODO: wrap error?
			return err
		}

		manifest, err := getManifest(ctx, dockerCLI, targetRef, namedRef, opts.insecure)
		if err != nil {
			return err
		}
		if err := manifestStore.Save(targetRef, namedRef, manifest); err != nil {
			return err
		}
	}
	_, _ = fmt.Fprintln(dockerCLI.Out(), "Created manifest list", targetRef.String())
	return nil
}
