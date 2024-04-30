package commands

import (
	"os"

	"github.com/docker/cli/cli/command"
	"github.com/docker/cli/cli/command/builder"
	"github.com/docker/cli/cli/command/checkpoint"
	"github.com/docker/cli/cli/command/completion"
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
	"github.com/spf13/cobra"
)

// AddCommands adds all the commands from cli/command to the root command
func AddCommands(cmd *cobra.Command, dockerCli command.Cli) {
	cmd.AddCommand(
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

		// completion command
		completion.NewCompletionCommand(dockerCli),

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
