package support

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"time"
)

func RunCommand(in io.Reader, out io.Writer, dataDir, version string, now time.Time) error {
	reader := bufio.NewReader(in)
	line, err := reader.ReadString('\n')
	if err != nil && len(line) == 0 {
		return nil
	}
	line = strings.TrimSuffix(line, "\n")
	line = strings.TrimSuffix(line, "\r")
	if line != "go" {
		return nil
	}
	fmt.Fprintln(out, "Creating support data ... please wait")
	path, err := CreateArchive(dataDir, version, now)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, path)
	return nil
}
