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

func (l *singLogger) Trace(args ...any) {
	if l.zapLogger == nil {
		return
	}
	l.zapLogger.Debug(l.tag, zap.Any("args", args))
}

func (l *singLogger) Debug(args ...any) {
	if l.zapLogger == nil {
		return
	}
	l.zapLogger.Debug(l.tag, zap.Any("args", args))
}

func (l *singLogger) Info(args ...any) {
	if l.zapLogger == nil {
		return
	}
	l.zapLogger.Info(l.tag, zap.Any("args", args))
}

func (l *singLogger) Warn(args ...any) {
	if l.zapLogger == nil {
		return
	}
	l.zapLogger.Warn(l.tag, zap.Any("args", args))
}

func (l *singLogger) Error(args ...any) {
	if l.zapLogger == nil {
		return
	}
	l.zapLogger.Error(l.tag, zap.Any("args", args))
}

func (l *singLogger) Fatal(args ...any) {
	if l.zapLogger == nil {
		return
	}
	l.zapLogger.Fatal(l.tag, zap.Any("args", args))
}

func (l *singLogger) Panic(args ...any) {
	if l.zapLogger == nil {
		return
	}
	l.zapLogger.Panic(l.tag, zap.Any("args", args))
}
