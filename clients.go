package main

import (
	"sync"

	"github.com/go-resty/resty/v2"
	"go.mau.fi/whatsmeow"
)

type ClientManager struct {
	sync.RWMutex
	whatsmeowClients map[string]*whatsmeow.Client
	httpClients      map[string]*resty.Client
	myClients        map[string]*MyClient
}

func NewClientManager() *ClientManager {
	return &ClientManager{
		whatsmeowClients: make(map[string]*whatsmeow.Client),
		httpClients:      make(map[string]*resty.Client),
		myClients:        make(map[string]*MyClient),
	}
}

func (cm *ClientManager) SetWhatsmeowClient(userID string, client *whatsmeow.Client) {
	cm.Lock()
	defer cm.Unlock()
	cm.whatsmeowClients[userID] = client
}

func (cm *ClientManager) GetWhatsmeowClient(userID string) *whatsmeow.Client {
	cm.RLock()
	defer cm.RUnlock()
	return cm.whatsmeowClients[userID]
}

func (cm *ClientManager) DeleteWhatsmeowClient(userID string) {
	cm.Lock()
	defer cm.Unlock()
	delete(cm.whatsmeowClients, userID)
}

func (cm *ClientManager) SetHTTPClient(userID string, client *resty.Client) {
	cm.Lock()
	defer cm.Unlock()
	cm.httpClients[userID] = client
}

func (cm *ClientManager) GetHTTPClient(userID string) *resty.Client {
	cm.RLock()
	defer cm.RUnlock()
	return cm.httpClients[userID]
}

func (cm *ClientManager) DeleteHTTPClient(userID string) {
	cm.Lock()
	defer cm.Unlock()
	delete(cm.httpClients, userID)
}

func (cm *ClientManager) SetMyClient(userID string, client *MyClient) {
	cm.Lock()
	defer cm.Unlock()
	cm.myClients[userID] = client
}

func (cm *ClientManager) GetMyClient(userID string) *MyClient {
	cm.RLock()
	defer cm.RUnlock()
	return cm.myClients[userID]
}

func (cm *ClientManager) DeleteMyClient(userID string) {
	cm.Lock()
	defer cm.Unlock()
	delete(cm.myClients, userID)
}

// UpdateMyClientSubscriptions updates the event subscriptions of a client without reconnecting
func (cm *ClientManager) UpdateMyClientSubscriptions(userID string, subscriptions []string) {
	cm.Lock()
	defer cm.Unlock()
	if client, exists := cm.myClients[userID]; exists {
		client.subscriptions = subscriptions
	}
}
