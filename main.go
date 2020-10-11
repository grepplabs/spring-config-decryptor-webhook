package main

import (
	"github.com/grepplabs/spring-config-decryptor-webhook/webhook"

	"flag"
	"github.com/spf13/cobra"
	"k8s.io/klog/v2"
)

func main() {
	rootCmd := &cobra.Command{
		Use: "spring-config-decryptor-webhook",
	}
	rootCmd.AddCommand(webhook.CmdWebhook)

	loggingFlags := &flag.FlagSet{}
	klog.InitFlags(loggingFlags)
	rootCmd.PersistentFlags().AddGoFlagSet(loggingFlags)
	rootCmd.Execute()
}
