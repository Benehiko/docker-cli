package config

import (
	"context"
	"fmt"
	"io"

	"github.com/docker/cli/cli"
	"github.com/docker/cli/cli/command"
	"github.com/docker/cli/cli/command/completion"
	"github.com/docker/cli/opts"
	"github.com/docker/docker/api/types/swarm"
	"github.com/moby/sys/sequential"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

// CreateOptions specifies some options that are used when creating a config.
type CreateOptions struct {
	Name           string
	TemplateDriver string
	File           string
	Labels         opts.ListOpts
}

func newConfigCreateCommand(dockerCli command.Cli) *cobra.Command {
	createOpts := CreateOptions{
		Labels: opts.NewListOpts(opts.ValidateLabel),
	}

	cmd := &cobra.Command{
		Use:   "create [OPTIONS] CONFIG file|-",
		Short: "Create a config from a file or STDIN",
		Args:  cli.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			createOpts.Name = args[0]
			createOpts.File = args[1]
			return RunConfigCreate(cmd.Context(), dockerCli, createOpts)
		},
		ValidArgsFunction: completion.NoComplete,
	}
	flags := cmd.Flags()
	flags.VarP(&createOpts.Labels, "label", "l", "Config labels")
	flags.StringVar(&createOpts.TemplateDriver, "template-driver", "", "Template driver")
	flags.SetAnnotation("template-driver", "version", []string{"1.37"})

	return cmd
}

// RunConfigCreate creates a config with the given options.
func RunConfigCreate(ctx context.Context, dockerCLI command.Cli, options CreateOptions) error {
	apiClient := dockerCLI.Client()

	var in io.Reader = dockerCLI.In()
	if options.File != "-" {
		file, err := sequential.Open(options.File)
		if err != nil {
			return err
		}
		in = file
		defer file.Close()
	}

	configData, err := io.ReadAll(in)
	if err != nil {
		return errors.Errorf("Error reading content from %q: %v", options.File, err)
	}

	spec := swarm.ConfigSpec{
		Annotations: swarm.Annotations{
			Name:   options.Name,
			Labels: opts.ConvertKVStringsToMap(options.Labels.GetAll()),
		},
		Data: configData,
	}
	if options.TemplateDriver != "" {
		spec.Templating = &swarm.Driver{
			Name: options.TemplateDriver,
		}
	}
	r, err := apiClient.ConfigCreate(ctx, spec)
	if err != nil {
		return err
	}

	fmt.Fprintln(dockerCLI.Out(), r.ID)
	return nil
}
