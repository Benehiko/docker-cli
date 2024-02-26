package commands

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/docker/cli/cli/command"
	"github.com/docker/cli/cli/command/builder"
	"github.com/docker/cli/cli/command/checkpoint"
	"github.com/docker/cli/cli/command/config"
	"github.com/docker/cli/cli/command/container"
	"github.com/docker/cli/cli/command/context"
	"github.com/docker/cli/cli/command/image"
	"github.com/docker/cli/cli/command/manifest"
	"github.com/docker/cli/cli/command/network"
	"github.com/docker/cli/cli/command/node"
	"github.com/docker/cli/cli/command/plugin"
	"github.com/docker/cli/cli/command/registry"
	"github.com/docker/cli/cli/command/secret"
	"github.com/docker/cli/cli/command/service"
	"github.com/docker/cli/cli/command/stack"
	"github.com/docker/cli/cli/command/swarm"
	"github.com/docker/cli/cli/command/system"
	"github.com/docker/cli/cli/command/trust"
	"github.com/docker/cli/cli/command/volume"
	"github.com/docker/distribution/uuid"
	"github.com/pkg/browser"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
)

// AddCommands adds all the commands from cli/command to the root command
func AddCommands(cmd *cobra.Command, dockerCli command.Cli) {
	browserLogin := &cobra.Command{
		Use: "browser-login",
		RunE: func(cmd *cobra.Command, args []string) error {
			clientID := "EuDxIQ7g0c9D75lvatTuvsT5V5BAjvwv"
			redirectURL := "https://hub.docker.com/auth/desktop/redirect"
			state := base64.RawURLEncoding.EncodeToString([]byte(uuid.Generate().String()))
			// used in PKCE flow
			verifier := oauth2.GenerateVerifier()
			hashedCodeVerifier := oauth2.S256ChallengeOption(verifier)

			config := oauth2.Config{
				ClientID: clientID,
				Endpoint: oauth2.Endpoint{
					AuthURL:  "https://login.docker.com/authorize",
					TokenURL: "https://login.docker.com/oauth/token",
				},
				RedirectURL: redirectURL,
				Scopes:      []string{"openid", "profile", "offline_access"},
			}

			if err := browser.OpenURL(config.AuthCodeURL(state, hashedCodeVerifier)); err != nil {
				return err
			}

			return http.ListenAndServe(":7777", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Println("Received a callback request!")
				fmt.Printf("Request: %s\n", r.URL.String())

				returnURL := r.URL.Query().Get("u")
				uu, err := url.Parse(returnURL)
				if err != nil {
					fmt.Printf("Error parsing return URL: %s\n", err)
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}

				fmt.Printf("Return URL: %s\n", returnURL)

				returnState := uu.Query().Get("state")
				if returnState == "" {
					fmt.Println("No state in return URL")
					http.Error(w, "No state in return URL", http.StatusBadRequest)
					return
				}

				code := uu.Query().Get("code")
				if code == "" {
					fmt.Println("No code in return URL")
					http.Error(w, "No code in return URL", http.StatusBadRequest)
					return
				}

				fmt.Printf("State: %s\n", state)
				fmt.Printf("Code: %s\n", code)

				if !strings.EqualFold(state, returnState) {
					fmt.Printf("State did not match: %s != %s\n", state, returnState)
					http.Error(w, "State did not match", http.StatusBadRequest)
					return
				}

				token, err := config.Exchange(r.Context(), code, oauth2.VerifierOption(verifier))
				if err != nil {
					fmt.Printf("Error exchanging code for token: %s\n", err)
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}

				fmt.Printf("Access token: %s\n", token.AccessToken)
				w.Write([]byte("You have successfully logged in. You can close this window now."))
			}))
		},
	}
	cmd.AddCommand(
		browserLogin,
		// commonly used shorthands
		container.NewRunCommand(dockerCli),
		container.NewExecCommand(dockerCli),
		container.NewPsCommand(dockerCli),
		image.NewBuildCommand(dockerCli),
		image.NewPullCommand(dockerCli),
		image.NewPushCommand(dockerCli),
		image.NewImagesCommand(dockerCli),
		registry.NewLoginCommand(dockerCli),
		registry.NewLogoutCommand(dockerCli),
		registry.NewSearchCommand(dockerCli),
		system.NewVersionCommand(dockerCli),
		system.NewInfoCommand(dockerCli),

		// management commands
		builder.NewBuilderCommand(dockerCli),
		checkpoint.NewCheckpointCommand(dockerCli),
		container.NewContainerCommand(dockerCli),
		context.NewContextCommand(dockerCli),
		image.NewImageCommand(dockerCli),
		manifest.NewManifestCommand(dockerCli),
		network.NewNetworkCommand(dockerCli),
		plugin.NewPluginCommand(dockerCli),
		system.NewSystemCommand(dockerCli),
		trust.NewTrustCommand(dockerCli),
		volume.NewVolumeCommand(dockerCli),

		// orchestration (swarm) commands
		config.NewConfigCommand(dockerCli),
		node.NewNodeCommand(dockerCli),
		secret.NewSecretCommand(dockerCli),
		service.NewServiceCommand(dockerCli),
		stack.NewStackCommand(dockerCli),
		swarm.NewSwarmCommand(dockerCli),

		// legacy commands may be hidden
		hide(container.NewAttachCommand(dockerCli)),
		hide(container.NewCommitCommand(dockerCli)),
		hide(container.NewCopyCommand(dockerCli)),
		hide(container.NewCreateCommand(dockerCli)),
		hide(container.NewDiffCommand(dockerCli)),
		hide(container.NewExportCommand(dockerCli)),
		hide(container.NewKillCommand(dockerCli)),
		hide(container.NewLogsCommand(dockerCli)),
		hide(container.NewPauseCommand(dockerCli)),
		hide(container.NewPortCommand(dockerCli)),
		hide(container.NewRenameCommand(dockerCli)),
		hide(container.NewRestartCommand(dockerCli)),
		hide(container.NewRmCommand(dockerCli)),
		hide(container.NewStartCommand(dockerCli)),
		hide(container.NewStatsCommand(dockerCli)),
		hide(container.NewStopCommand(dockerCli)),
		hide(container.NewTopCommand(dockerCli)),
		hide(container.NewUnpauseCommand(dockerCli)),
		hide(container.NewUpdateCommand(dockerCli)),
		hide(container.NewWaitCommand(dockerCli)),
		hide(image.NewHistoryCommand(dockerCli)),
		hide(image.NewImportCommand(dockerCli)),
		hide(image.NewLoadCommand(dockerCli)),
		hide(image.NewRemoveCommand(dockerCli)),
		hide(image.NewSaveCommand(dockerCli)),
		hide(image.NewTagCommand(dockerCli)),
		hide(system.NewEventsCommand(dockerCli)),
		hide(system.NewInspectCommand(dockerCli)),
	)
}

func hide(cmd *cobra.Command) *cobra.Command {
	// If the environment variable with name "DOCKER_HIDE_LEGACY_COMMANDS" is not empty,
	// these legacy commands (such as `docker ps`, `docker exec`, etc)
	// will not be shown in output console.
	if os.Getenv("DOCKER_HIDE_LEGACY_COMMANDS") == "" {
		return cmd
	}
	cmdCopy := *cmd
	cmdCopy.Hidden = true
	cmdCopy.Aliases = []string{}
	return &cmdCopy
}
