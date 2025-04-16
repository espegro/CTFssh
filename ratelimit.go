package main

import (
	"log"
	"sync"
	"time"
)

type LoginAttempt struct {
	Count      int
	LastFail   time.Time
	LastTry    time.Time
	Blocked    bool
}

var (
	rateLock sync.Mutex
	ipFailures = make(map[string]*LoginAttempt)
	userFailures = make(map[string]*LoginAttempt)
)

const (
	maxFailsPerIP     = 5
	maxFailsPerUser   = 10
	blockDuration     = 1 * time.Minute
)

func isBlocked(ip string, username string) bool {
	rateLock.Lock()
	defer rateLock.Unlock()

	now := time.Now()

	if ipInfo, ok := ipFailures[ip]; ok {
		if ipInfo.Blocked {
			if now.Sub(ipInfo.LastFail) >= blockDuration {
				// Blokkering utløpt
				ipInfo.Blocked = false
				ipInfo.Count = 0
				log.Printf("Block lifted for IP: %s", ip)
			} else {
				return true
			}
		}
	}

	if userInfo, ok := userFailures[username]; ok {
		if userInfo.Blocked {
			if now.Sub(userInfo.LastFail) >= blockDuration {
				// Blokkering utløpt
				userInfo.Blocked = false
				userInfo.Count = 0
				log.Printf("Block lifted for user: %s", username)
			} else {
				return true
			}
		}
	}

	return false
}

func registerAuthFail(ip string, username string) {
	rateLock.Lock()
	defer rateLock.Unlock()

	now := time.Now()

	ipInfo := ipFailures[ip]
	if ipInfo == nil {
		ipInfo = &LoginAttempt{}
		ipFailures[ip] = ipInfo
	}
	ipInfo.Count++
	ipInfo.LastFail = now
	ipInfo.LastTry = now
	if ipInfo.Count >= maxFailsPerIP {
		ipInfo.Blocked = true
		log.Printf("Too many failures from IP %s – temporarily blocked", ip)
	}

	userInfo := userFailures[username]
	if userInfo == nil {
		userInfo = &LoginAttempt{}
		userFailures[username] = userInfo
	}
	userInfo.Count++
	userInfo.LastFail = now
	userInfo.LastTry = now
	if userInfo.Count >= maxFailsPerUser {
		userInfo.Blocked = true
		log.Printf("Too many failures for user %s – temporarily blocked", username)
	}
}

func registerAuthSuccess(ip string, username string) {
	rateLock.Lock()
	defer rateLock.Unlock()

	delete(ipFailures, ip)
	delete(userFailures, username)
}

