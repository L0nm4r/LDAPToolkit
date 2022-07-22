package logger

import (
	"fmt"
	"github.com/mattn/go-colorable"
	"os"
	"sync"
)

var sem sync.Mutex
var DebugMode = false

func Info(format string, a ...interface{})  {
	StdOut(Green("[i] "+format+"\n",a...))
}

func Key(format string, a ...interface{})  {
	StdOut(Carmine(format,a...))
}

func Warn(format string, a ...interface{})  {
	StdOut(Yellow("[!] "+format+"\n",a...))
}

func Debug(format string, a ...interface{})  {
	if DebugMode {
		StdOut(Blue("[*] "+format+"\n",a...))
	}
}

func Error(format string, a ...interface{})  {
	StdOut(Red("[X] "+format+"\n",a...))
}

func Out(format string, a ...interface{}) {
	StdOut(Green("[+] "+format+"\n",a...))
}

func Red(format string, a ...interface{}) string{
	return fmt.Sprintf("\x1b[31m"+format+"\x1b[0m",a...)
}

func Green(format string, a ...interface{}) string{
	return fmt.Sprintf("\x1b[32m"+format+"\x1b[0m",a...)
}

func Yellow(format string, a ...interface{}) string{
	return fmt.Sprintf("\x1b[33m"+format+"\x1b[0m",a...)
}

func Blue(format string, a ...interface{}) string{
	return fmt.Sprintf("\x1b[34m"+format+"\x1b[0m",a...)
}

func Carmine(format string, a ...interface{}) string{
	return fmt.Sprintf("\x1b[35m"+format+"\x1b[0m",a...)
}

func Cyan(format string, a ...interface{}) string{
	return fmt.Sprintf("\x1b[36m"+format+"\x1b[0m",a...)
}

func StdOut(s string,a...interface{}){
	sem.Lock()
	stdout := colorable.NewColorable(os.Stdout)
	fmt.Fprintf(stdout,s,a...)
	sem.Unlock()
}