// @Time    : 2022/10/13 1:56 PM
// @Author  : HuYuan
// @File    : compatible.go
// @Email   : huyuan@virtaitech.com

package compatible

import (
	"errors"
	"fmt"
	"github.com/NVIDIA/nvidia-container-toolkit/compatible/runcv100rc2"
	oldspecs "github.com/NVIDIA/nvidia-container-toolkit/compatible/runcv100rc2/specs-go"
	"github.com/buger/jsonparser"
	newspecs "github.com/opencontainers/runtime-spec/specs-go"
	"io"
	"io/ioutil"
	"os"
	"strings"
)

type Compatible interface {
	Decode() (io.Reader, error)
	Encode(*newspecs.Spec) (*oldspecs.Spec, error)
}

var (
	ErrUnknownOCIVersion = errors.New("unknown oci version")
)

func NewCompatible(specFile *os.File) (Compatible, error) {
	spec, err := ioutil.ReadAll(specFile)
	if err != nil {
		return nil, fmt.Errorf("error read spec file: %v", err)
	}
	ociVersion, err := jsonparser.GetString(spec, "ociVersion")
	if err != nil {
		return nil, fmt.Errorf("error get ociVersion: %v", err)
	}
	switch {
	case strings.Contains(ociVersion, "1.0.0-rc2"):
		return runcv100rc2.NewCompatible(spec), nil
	default:
		return nil, ErrUnknownOCIVersion
	}
}
