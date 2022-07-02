// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build functionaltests
// +build functionaltests

package tests

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	"github.com/DataDog/datadog-agent/pkg/security/secl/rules"
)

func TestActivityDumps(t *testing.T) {
	ruleDefs := []*rules.RuleDefinition{
		{
			ID:         "activating_network_probe",
			Expression: `bind.addr.family == AF_INET && bind.addr.port == 1`,
		},
	}

	test, err := newTestModule(t, nil, ruleDefs, testOpts{enableActivityDump: true})
	if err != nil {
		t.Fatal(err)
	}
	defer test.Close()
	syscallTester, err := loadSyscallTester(t, test, "syscall_tester")
	if err != nil {
		t.Fatal(err)
	}
	outputDir, _, err := test.Path("test-activity-dump")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(outputDir)

	test.Run(t, "activity-dump-comm-bind", func(t *testing.T, kind wrapperType,
		cmdFunc func(cmd string, args []string, envs []string) *exec.Cmd) {

		outputFiles, err := test.StartActivityDumpComm(t, "syscall_tester", outputDir, []string{"json", "msgp"})
		if err != nil {
			t.Fatal(err)
		}

		args := []string{"bind", "AF_INET", "any", "tcp"}
		envs := []string{}
		cmd := cmdFunc(syscallTester, args, envs)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatal(fmt.Errorf("%s: %w", out, err))
		}

		time.Sleep(1 * time.Second) // a quick sleep to let events to be added to the dump

		err = test.StopActivityDumpComm(t, "syscall_tester")
		if err != nil {
			t.Fatal(err)
		}

		jsonOK := false
		msgpOK := false
		for _, f := range outputFiles {
			ext := filepath.Ext(f)
			switch ext {
			case ".json":
				if jsonOK == true {
					t.Fatal("Got more than one JSON file:", outputFiles)
				}
				content, err := os.ReadFile(f)
				if err != nil {
					t.Fatal(err)
				}
				if !validateActivityDumpSchema(t, string(content)) {
					t.Error(string(content))
				}
				jsonOK = true

			case ".msgp":
				if msgpOK == true {
					t.Fatal("Got more than one MSGP file:", outputFiles)
				}
				ad, err := test.DecodeMSPActivityDump(t, f)
				if err != nil {
					t.Fatal(err)
				}
				node := ad.FindFirstMatchingNode("syscall_tester")
				if node == nil {
					t.Fatal("Node not found in activity dump")
				}
				for _, s := range node.Sockets {
					if s.Family == "AF_INET" && s.Bind.Port == 4242 && s.Bind.IP == "0.0.0.0" {
						msgpOK = true
						break
					}
				}
				if msgpOK == false {
					t.Error("Bound socket not found in activity dump")
				}

			default:
				t.Fatal("Unexpected output file")
			}

		}
		if jsonOK == false || msgpOK == false {
			t.Fatal("Some data is missing, got:", outputFiles)
		}
	})

	test.Run(t, "activity-dump-comm-dns", func(t *testing.T, kind wrapperType,
		cmdFunc func(cmd string, args []string, envs []string) *exec.Cmd) {

		outputFiles, err := test.StartActivityDumpComm(t, "testsuite", outputDir, []string{"json", "msgp"})
		if err != nil {
			t.Fatal(err)
		}

		net.LookupIP("foo.bar")

		time.Sleep(1 * time.Second) // a quick sleep to let events to be added to the dump

		err = test.StopActivityDumpComm(t, "testsuite")
		if err != nil {
			t.Fatal(err)
		}

		jsonOK := false
		msgpOK := false
		for _, f := range outputFiles {
			ext := filepath.Ext(f)
			switch ext {
			case ".json":
				if jsonOK == true {
					t.Fatal("Got more than one JSON file:", outputFiles)
				}
				content, err := os.ReadFile(f)
				if err != nil {
					t.Fatal(err)
				}
				if !validateActivityDumpSchema(t, string(content)) {
					t.Error(string(content))
				}
				jsonOK = true

			case ".msgp":
				if msgpOK == true {
					t.Fatal("Got more than one MSGP file:", outputFiles)
				}
				ad, err := test.DecodeMSPActivityDump(t, f)
				if err != nil {
					t.Fatal(err)
				}
				node := ad.FindFirstMatchingNode("testsuite")
				if node == nil {
					t.Fatal("Node not found in activity dump")
				}
				for name := range node.DNSNames {
					if name == "foo.bar" {
						msgpOK = true
						break
					}
				}
				if msgpOK == false {
					t.Error("DNS request not found in activity dump")
				}

			default:
				t.Fatal("Unexpected output file")
			}

		}
		if jsonOK == false || msgpOK == false {
			t.Fatal("Some data is missing, got:", outputFiles)
		}
	})

	test.Run(t, "activity-dump-comm-syscalls", func(t *testing.T, kind wrapperType,
		cmdFunc func(cmd string, args []string, envs []string) *exec.Cmd) {

		outputFiles, err := test.StartActivityDumpComm(t, "syscall_tester", outputDir, []string{"json", "msgp"})
		if err != nil {
			t.Fatal(err)
		}

		args := []string{"bind", "AF_INET", "any", "tcp"}
		envs := []string{}
		cmd := cmdFunc(syscallTester, args, envs)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatal(fmt.Errorf("%s: %w", out, err))
		}

		time.Sleep(1 * time.Second) // a quick sleep to let events to be added to the dump

		err = test.StopActivityDumpComm(t, "syscall_tester")
		if err != nil {
			t.Fatal(err)
		}

		jsonOK := false
		msgpOK := false
		for _, f := range outputFiles {
			ext := filepath.Ext(f)
			switch ext {
			case ".json":
				if jsonOK == true {
					t.Fatal("Got more than one JSON file:", outputFiles)
				}
				content, err := os.ReadFile(f)
				if err != nil {
					t.Fatal(err)
				}
				if !validateActivityDumpSchema(t, string(content)) {
					t.Error(string(content))
				}
				jsonOK = true

			case ".msgp":
				if msgpOK == true {
					t.Fatal("Got more than one MSGP file:", outputFiles)
				}
				ad, err := test.DecodeMSPActivityDump(t, f)
				if err != nil {
					t.Fatal(err)
				}
				node := ad.FindFirstMatchingNode("syscall_tester")
				if node == nil {
					t.Fatal("Node not found in activity dump")
				}
				var exitOK, execveOK bool
				for _, s := range node.Syscalls {
					if s == int(model.SysExit) || s == int(model.SysExitGroup) {
						exitOK = true
					}
					if s == int(model.SysExecve) || s == int(model.SysExecveat) {
						execveOK = true
					}
				}
				if !exitOK {
					t.Errorf("exit syscall not found in activity dump: %+v", node.Syscalls)
				} else {
					if !execveOK {
						t.Errorf("execve syscall not found in activity dump: %+v", node.Syscalls)
					} else {
						msgpOK = true
					}
				}

			default:
				t.Fatal("Unexpected output file")
			}

		}
		if jsonOK == false || msgpOK == false {
			t.Fatal("Some data is missing, got:", outputFiles)
		}
	})
}
