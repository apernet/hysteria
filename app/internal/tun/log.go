package tun

import (
	"github.com/sagernet/sing/common/logger"
	"go.uber.org/zap"
)

var _ logger.Logger = (*singLogger)(nil)

type singLogger struct {
	tag       string
	zapLogger *zap.Logger
}

func extractSingExceptions(args []any) {
	for i, arg := range args {
		if err, ok := arg.(error); ok {
			args[i] = err.Error()
		}
	}
}

func (l *singLogger) Trace(args ...any) {
	if l.zapLogger == nil {
		return
	}
	extractSingExceptions(args)
	l.zapLogger.Debug(l.tag, zap.Any("args", args))
}

func (l *singLogger) Debug(args ...any) {
	if l.zapLogger == nil {
		return
	}
	extractSingExceptions(args)
	l.zapLogger.Debug(l.tag, zap.Any("args", args))
}

func (l *singLogger) Info(args ...any) {
	if l.zapLogger == nil {
		return
	}
	extractSingExceptions(args)
	l.zapLogger.Info(l.tag, zap.Any("args", args))
}

func (l *singLogger) Warn(args ...any) {
	if l.zapLogger == nil {
		return
	}
	extractSingExceptions(args)
	l.zapLogger.Warn(l.tag, zap.Any("args", args))
}

func (l *singLogger) Error(args ...any) {
	if l.zapLogger == nil {
		return
	}
	extractSingExceptions(args)
	l.zapLogger.Error(l.tag, zap.Any("args", args))
}

func (l *singLogger) Fatal(args ...any) {
	if l.zapLogger == nil {
		return
	}
	extractSingExceptions(args)
	l.zapLogger.Fatal(l.tag, zap.Any("args", args))
}

func (l *singLogger) Panic(args ...any) {
	if l.zapLogger == nil {
		return
	}
	extractSingExceptions(args)
	l.zapLogger.Panic(l.tag, zap.Any("args", args))
}
