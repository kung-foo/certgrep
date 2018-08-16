package certgrep

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"
)

type Option func(*Extractor) error

func Logger(logger *zap.SugaredLogger) Option {
	return func(e *Extractor) (err error) {
		e.logger = logger.Named("certgrep")
		return
	}
}

func OutputDir(dir string) Option {
	// TODO(jca): check env SUDO_UID|GID and reset?
	return func(e *Extractor) (err error) {
		dir, err = filepath.Abs(dir)
		if err != nil {
			return
		}

		now := strings.Replace(time.Now().UTC().Format(time.RFC3339), ":", "_", -1)
		e.outputOptions.dir = path.Join(dir, now)

		return os.MkdirAll(e.outputOptions.dir, defaultDirPerm)
	}
}

func LogToStdout(do bool) Option {
	return func(e *Extractor) (err error) {
		e.logToStdout = do
		return nil
	}
}

func EnableOutputFormat(format string, do bool) Option {
	return func(e *Extractor) (err error) {
		switch format {
		case "json":
			e.outputOptions.json = do
		case "der":
			e.outputOptions.der = do
		case "pem":
			e.outputOptions.pem = do
		default:
			return fmt.Errorf("invalid format")
		}
		return
	}
}
