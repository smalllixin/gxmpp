package gxmpp
import (
	"log"
	"syscall"
)


func SuperRlimit(cur,max uint64) {
    var rLimit syscall.Rlimit
    err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
    if err != nil {
        log.Fatalf("Error Getting Rlimit:%v\n", err)
    }
    
    if cur > rLimit.Cur {
    	rLimit.Cur = cur
    }
    if max > rLimit.Max {
    	rLimit.Max = max
    }
    
    err = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
    if err != nil {
        log.Fatalf("Error Setting Rlimit:%v\n", err)
    }
    err = syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
    if err != nil {
        log.Fatalf("Error Getting Rlimit:%v\n", err)
    }
    log.Println("Rlimit Final", rLimit)
}