// @Time    : 2022/10/13 10:22 AM
// @Author  : HuYuan
// @File    : compatible.go
// @Email   : huyuan@virtaitech.com

package runcv100rc2

import (
	"bytes"
	"encoding/json"
	"fmt"
	oldspecs "github.com/NVIDIA/nvidia-container-toolkit/compatible/runcv100rc2/specs-go"
	newspecs "github.com/opencontainers/runtime-spec/specs-go"
	"io"
	"reflect"
	"strings"
)

type Compatible struct {
	spec          []byte
	os            string
	arch          string
	eraseSyscalls bool
	eraseCaps     bool
}

func validateField(obj interface{}, field string) bool {
	if obj == nil {
		return false
	}

	v := reflect.ValueOf(obj)

	for _, name := range strings.Split(field, ".") {
		if v.Kind() == reflect.Ptr {
			v = v.Elem().FieldByName(name)
		} else {
			v = v.FieldByName(name)
		}

		switch v.Kind() {
		case reflect.Ptr, reflect.Map, reflect.Slice:
			if v.IsNil() {
				return false
			}
		default:
			return true
		}
	}
	return true
}

func NewCompatible(spec []byte) *Compatible {
	return &Compatible{spec: spec}
}

func (c *Compatible) eraseDecodeSyscallsDiff(oldSyscalls []oldspecs.Syscall) []newspecs.LinuxSyscall {
	var compatibleSyscalls []newspecs.LinuxSyscall
	if oldSyscalls == nil {
		return nil
	}

	for _, syscall := range oldSyscalls {
		var compatibleSyscallArgs []newspecs.LinuxSeccompArg
		for _, arg := range syscall.Args {
			seccompArg := newspecs.LinuxSeccompArg{
				Index:    arg.Index,
				Value:    arg.Value,
				ValueTwo: arg.ValueTwo,
				Op:       newspecs.LinuxSeccompOperator(arg.Op),
			}
			compatibleSyscallArgs = append(compatibleSyscallArgs, seccompArg)
		}
		newSyscall := newspecs.LinuxSyscall{
			Names:    []string{syscall.Name},
			Action:   newspecs.LinuxSeccompAction(syscall.Action),
			ErrnoRet: nil,
			Args:     compatibleSyscallArgs,
		}
		compatibleSyscalls = append(compatibleSyscalls, newSyscall)
	}
	return compatibleSyscalls
}

func (c *Compatible) eraseDecodeCapabilitiesDiff(oldCapabilities []string) *newspecs.LinuxCapabilities {
	return &newspecs.LinuxCapabilities{
		Bounding:    oldCapabilities,
		Effective:   oldCapabilities,
		Inheritable: oldCapabilities,
		Permitted:   oldCapabilities,
		Ambient:     oldCapabilities,
	}
}

func (c *Compatible) eraseEncodeSyscallsDiff(newSyscalls []newspecs.LinuxSyscall) []oldspecs.Syscall {
	var oldSyscalls []oldspecs.Syscall
	if newSyscalls == nil {
		return nil
	}

	for _, syscall := range newSyscalls {
		var compatibleSyscallArgs []oldspecs.Arg
		for _, arg := range syscall.Args {
			seccompArg := oldspecs.Arg{
				Index:    arg.Index,
				Value:    arg.Value,
				ValueTwo: arg.ValueTwo,
				Op:       oldspecs.Operator(arg.Op),
			}
			compatibleSyscallArgs = append(compatibleSyscallArgs, seccompArg)
		}

		oldSyscall := oldspecs.Syscall{
			Name:   syscall.Names[0],
			Action: oldspecs.Action(syscall.Action),
			Args:   compatibleSyscallArgs,
		}
		oldSyscalls = append(oldSyscalls, oldSyscall)
	}
	return oldSyscalls
}

func (c *Compatible) eraseEncodeCapabilitiesDiff(newCapabilities *newspecs.LinuxCapabilities) []string {
	if newCapabilities == nil {
		return nil
	}
	return newCapabilities.Effective
}

func (c *Compatible) Decode() (reader io.Reader, err error) {
	var oldSpec oldspecs.Spec
	var newSpec newspecs.Spec
	var intermediate newspecs.Spec

	if err = json.Unmarshal(c.spec, &oldSpec); err != nil {
		return nil, fmt.Errorf("error compatible runc v1.0.0-rc2 decode spec file: %v", err)
	}

	c.os = oldSpec.Platform.OS
	c.arch = oldSpec.Platform.Arch

	if validateField(oldSpec, "Linux.Seccomp.Syscalls") {
		intermediate.Linux = &newspecs.Linux{
			Seccomp: &newspecs.LinuxSeccomp{
				Syscalls: c.eraseDecodeSyscallsDiff(oldSpec.Linux.Seccomp.Syscalls),
			},
		}
		oldSpec.Linux.Seccomp.Syscalls = nil
		c.eraseSyscalls = true
	}

	if validateField(oldSpec, "Process.Capabilities") {
		intermediate.Process = &newspecs.Process{
			Capabilities: c.eraseDecodeCapabilitiesDiff(oldSpec.Process.Capabilities),
		}
		oldSpec.Process.Capabilities = nil
		c.eraseCaps = true
	}

	erase, err := json.Marshal(&oldSpec)
	if err != nil {
		return nil, fmt.Errorf("error marshal old spec: %v", err)
	}

	if err := json.Unmarshal(erase, &newSpec); err != nil {
		return nil, fmt.Errorf("error unmarshal old spec to new spec: %v", err)
	}

	if c.eraseSyscalls {
		newSpec.Linux.Seccomp.Syscalls = intermediate.Linux.Seccomp.Syscalls
	}

	if c.eraseCaps {
		newSpec.Process.Capabilities = intermediate.Process.Capabilities
	}

	spec, err := json.Marshal(&newSpec)
	if err != nil {
		return nil, fmt.Errorf("error marshal new spec: %v", err)
	}
	return bytes.NewBuffer(spec), nil
}

func (c *Compatible) Encode(newSpec *newspecs.Spec) (*oldspecs.Spec, error) {
	var oldSpec oldspecs.Spec
	var intermediate oldspecs.Spec

	if c.eraseSyscalls {
		intermediate.Linux = &oldspecs.Linux{
			Seccomp: &oldspecs.Seccomp{
				Syscalls: c.eraseEncodeSyscallsDiff(newSpec.Linux.Seccomp.Syscalls),
			},
		}
		newSpec.Linux.Seccomp.Syscalls = nil
	}

	if c.eraseCaps {
		intermediate.Process = oldspecs.Process{
			Capabilities: c.eraseEncodeCapabilitiesDiff(newSpec.Process.Capabilities),
		}
		newSpec.Process.Capabilities = nil
	}

	erase, err := json.Marshal(newSpec)
	if err != nil {
		return nil, fmt.Errorf("error marshal new spec: %v", err)
	}

	if err := json.Unmarshal(erase, &oldSpec); err != nil {
		return nil, fmt.Errorf("error unmarshal new spec to old spec: %v", err)
	}

	if c.eraseSyscalls {
		oldSpec.Linux.Seccomp.Syscalls = intermediate.Linux.Seccomp.Syscalls
	}

	if c.eraseCaps {
		oldSpec.Process.Capabilities = intermediate.Process.Capabilities
	}

	oldSpec.Platform.OS = c.os
	oldSpec.Platform.Arch = c.arch
	return &oldSpec, nil
}
