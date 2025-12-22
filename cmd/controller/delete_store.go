package main

import (
	"sync"
	"time"
)

type deleteRequest struct {
	Node         string
	DeleteRoutes bool
	RouteIDs     []uint
	RouteNames   []string
	RequestedAt  time.Time
}

var (
	deleteMu       sync.Mutex
	deleteRequests = make(map[string]*deleteRequest)
)

func storeDeleteRequest(req *deleteRequest) {
	deleteMu.Lock()
	defer deleteMu.Unlock()
	deleteRequests[req.Node] = req
}

func getDeleteRequest(node string) *deleteRequest {
	deleteMu.Lock()
	defer deleteMu.Unlock()
	return deleteRequests[node]
}

func clearDeleteRequest(node string) {
	deleteMu.Lock()
	defer deleteMu.Unlock()
	delete(deleteRequests, node)
}
