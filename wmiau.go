package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/jmoiron/sqlx"
	"github.com/mdp/qrterminal/v3"
	"github.com/patrickmn/go-cache"
	"github.com/rs/zerolog/log"
	"github.com/skip2/go-qrcode"
	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/appstate"
	"go.mau.fi/whatsmeow/proto/waCompanionReg"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	waLog "go.mau.fi/whatsmeow/util/log"
)

var historySyncID int32

// Declaração do campo db como *sqlx.DB
type MyClient struct {
	WAClient       *whatsmeow.Client
	eventHandlerID uint32
	userID         string
	token          string
	subscriptions  []string
	db             *sqlx.DB
}

// Connects to Whatsapp Websocket on server startup if last state was connected
func (s *server) connectOnStartup() {
	rows, err := s.db.Queryx("SELECT id,name,token,jid,webhook,events,proxy_url FROM users WHERE connected=1")
	if err != nil {
		log.Error().Err(err).Msg("DB Problem")
		return
	}
	defer rows.Close()
	for rows.Next() {
		txtid := ""
		token := ""
		jid := ""
		name := ""
		webhook := ""
		events := ""
		proxy_url := ""
		err = rows.Scan(&txtid, &name, &token, &jid, &webhook, &events, &proxy_url)
		if err != nil {
			log.Error().Err(err).Msg("DB Problem")
			return
		} else {
			log.Info().Str("token", token).Msg("Connect to Whatsapp on startup")
			v := Values{map[string]string{
				"Id":      txtid,
				"Name":    name,
				"Jid":     jid,
				"Webhook": webhook,
				"Token":   token,
				"Proxy":   proxy_url,
				"Events":  events,
			}}
			userinfocache.Set(token, v, cache.NoExpiration)
			// Gets and set subscription to webhook events
			eventarray := strings.Split(events, ",")

			var subscribedEvents []string
			if len(eventarray) == 1 && eventarray[0] == "" {
				subscribedEvents = []string{}
			} else {
				for _, arg := range eventarray {
					if !Find(supportedEventTypes, arg) {
						log.Warn().Str("Type", arg).Msg("Event type discarded")
						continue
					}
					if !Find(subscribedEvents, arg) {
						subscribedEvents = append(subscribedEvents, arg)
					}
				}

			}
			eventstring := strings.Join(subscribedEvents, ",")
			log.Info().Str("events", eventstring).Str("jid", jid).Msg("Attempt to connect")
			killchannel[txtid] = make(chan bool)
			go s.startClient(txtid, jid, token, subscribedEvents)

			// Initialize S3 client if configured
			go func(userID string) {
				var s3Config struct {
					Enabled       bool   `db:"s3_enabled"`
					Endpoint      string `db:"s3_endpoint"`
					Region        string `db:"s3_region"`
					Bucket        string `db:"s3_bucket"`
					AccessKey     string `db:"s3_access_key"`
					SecretKey     string `db:"s3_secret_key"`
					PathStyle     bool   `db:"s3_path_style"`
					PublicURL     string `db:"s3_public_url"`
					RetentionDays int    `db:"s3_retention_days"`
				}

				err := s.db.Get(&s3Config, `
					SELECT s3_enabled, s3_endpoint, s3_region, s3_bucket, 
						   s3_access_key, s3_secret_key, s3_path_style, 
						   s3_public_url, s3_retention_days
					FROM users WHERE id = $1`, userID)

				if err != nil {
					log.Error().Err(err).Str("userID", userID).Msg("Failed to get S3 config")
					return
				}

				if s3Config.Enabled {
					config := &S3Config{
						Enabled:       s3Config.Enabled,
						Endpoint:      s3Config.Endpoint,
						Region:        s3Config.Region,
						Bucket:        s3Config.Bucket,
						AccessKey:     s3Config.AccessKey,
						SecretKey:     s3Config.SecretKey,
						PathStyle:     s3Config.PathStyle,
						PublicURL:     s3Config.PublicURL,
						RetentionDays: s3Config.RetentionDays,
					}

					err = GetS3Manager().InitializeS3Client(userID, config)
					if err != nil {
						log.Error().Err(err).Str("userID", userID).Msg("Failed to initialize S3 client on startup")
					} else {
						log.Info().Str("userID", userID).Msg("S3 client initialized on startup")
					}
				}
			}(txtid)
		}
	}
	err = rows.Err()
	if err != nil {
		log.Error().Err(err).Msg("DB Problem")
	}
}

func parseJID(arg string) (types.JID, bool) {
	if arg[0] == '+' {
		arg = arg[1:]
	}
	if !strings.ContainsRune(arg, '@') {
		return types.NewJID(arg, types.DefaultUserServer), true
	} else {
		recipient, err := types.ParseJID(arg)
		if err != nil {
			log.Error().Err(err).Msg("Invalid JID")
			return recipient, false
		} else if recipient.User == "" {
			log.Error().Err(err).Msg("Invalid JID no server specified")
			return recipient, false
		}
		return recipient, true
	}
}

func (s *server) startClient(userID string, textjid string, token string, subscriptions []string) {
	log.Info().Str("userid", userID).Str("jid", textjid).Msg("Starting websocket connection to Whatsapp")

	var deviceStore *store.Device
	var err error

	// First handle the device store initialization
	if textjid != "" {
		jid, _ := parseJID(textjid)
		deviceStore, err = container.GetDevice(context.Background(), jid)
		if err != nil {
			log.Error().Err(err).Msg("Failed to get device")
			deviceStore = container.NewDevice()
		}
	} else {
		log.Warn().Msg("No jid found. Creating new device")
		deviceStore = container.NewDevice()
	}

	if deviceStore == nil {
		log.Warn().Msg("No store found. Creating new one")
		deviceStore = container.NewDevice()
	}

	clientLog := waLog.Stdout("Client", *waDebug, *colorOutput)

	// Create the client with initialized deviceStore
	var client *whatsmeow.Client
	if *waDebug != "" {
		client = whatsmeow.NewClient(deviceStore, clientLog)
	} else {
		client = whatsmeow.NewClient(deviceStore, nil)
	}

	// Now we can use the client with the manager
	clientManager.SetWhatsmeowClient(userID, client)
	if textjid != "" {
		jid, _ := parseJID(textjid)
		deviceStore, err = container.GetDevice(context.Background(), jid)
		if err != nil {
			panic(err)
		}
	} else {
		log.Warn().Msg("No jid found. Creating new device")
		deviceStore = container.NewDevice()
	}

	store.DeviceProps.PlatformType = waCompanionReg.DeviceProps_UNKNOWN.Enum()
	store.DeviceProps.Os = osName

	clientManager.SetWhatsmeowClient(userID, client)
	mycli := MyClient{client, 1, userID, token, subscriptions, s.db}
	mycli.eventHandlerID = mycli.WAClient.AddEventHandler(mycli.myEventHandler)

	// CORREÇÃO: Armazenar o MyClient no clientManager
	clientManager.SetMyClient(userID, &mycli)

	httpClient := resty.New()
	httpClient.SetRedirectPolicy(resty.FlexibleRedirectPolicy(15))
	if *waDebug == "DEBUG" {
		httpClient.SetDebug(true)
	}
	httpClient.SetTimeout(30 * time.Second)
	httpClient.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	httpClient.OnError(func(req *resty.Request, err error) {
		if v, ok := err.(*resty.ResponseError); ok {
			// v.Response contains the last response from the server
			// v.Err contains the original error
			log.Debug().Str("response", v.Response.String()).Msg("resty error")
			log.Error().Err(v.Err).Msg("resty error")
		}
	})

	// NEW: set proxy if defined in DB (assumes users table contains proxy_url column)
	var proxyURL string
	err = s.db.Get(&proxyURL, "SELECT proxy_url FROM users WHERE id=$1", userID)
	if err == nil && proxyURL != "" {
		httpClient.SetProxy(proxyURL)
	}
	clientManager.SetHTTPClient(userID, httpClient)

	if client.Store.ID == nil {
		// No ID stored, new login
		qrChan, err := client.GetQRChannel(context.Background())
		if err != nil {
			// This error means that we're already logged in, so ignore it.
			if !errors.Is(err, whatsmeow.ErrQRStoreContainsID) {
				log.Error().Err(err).Msg("Failed to get QR channel")
				return
			}
		} else {
			err = client.Connect() // Si no conectamos no se puede generar QR
			if err != nil {
				log.Error().Err(err).Msg("Failed to connect client")
				return
			}

			myuserinfo, found := userinfocache.Get(token)

			for evt := range qrChan {
				if evt.Event == "code" {
					// Display QR code in terminal (useful for testing/developing)
					if *logType != "json" {
						qrterminal.GenerateHalfBlock(evt.Code, qrterminal.L, os.Stdout)
						fmt.Println("QR code:\n", evt.Code)
					}
					// Store encoded/embeded base64 QR on database for retrieval with the /qr endpoint
					image, _ := qrcode.Encode(evt.Code, qrcode.Medium, 256)
					base64qrcode := "data:image/png;base64," + base64.StdEncoding.EncodeToString(image)
					sqlStmt := `UPDATE users SET qrcode=$1 WHERE id=$2`
					_, err := s.db.Exec(sqlStmt, base64qrcode, userID)
					if err != nil {
						log.Error().Err(err).Msg(sqlStmt)
					} else {
						if found {
							v := updateUserInfo(myuserinfo, "Qrcode", base64qrcode)
							userinfocache.Set(token, v, cache.NoExpiration)
							log.Info().Str("qrcode", base64qrcode).Msg("update cache userinfo with qr code")
						}
					}
				} else if evt.Event == "timeout" {
					// Clear QR code from DB on timeout
					sqlStmt := `UPDATE users SET qrcode='' WHERE id=$1`
					_, err := s.db.Exec(sqlStmt, userID)
					if err != nil {
						log.Error().Err(err).Msg(sqlStmt)
					} else {
						if found {
							v := updateUserInfo(myuserinfo, "Qrcode", "")
							userinfocache.Set(token, v, cache.NoExpiration)
						}
					}
					log.Warn().Msg("QR timeout killing channel")
					clientManager.DeleteWhatsmeowClient(userID)
					clientManager.DeleteMyClient(userID)
					clientManager.DeleteHTTPClient(userID)
					killchannel[userID] <- true
				} else if evt.Event == "success" {
					log.Info().Msg("QR pairing ok!")
					// Clear QR code after pairing
					sqlStmt := `UPDATE users SET qrcode='', connected=1 WHERE id=$1`
					_, err := s.db.Exec(sqlStmt, userID)
					if err != nil {
						log.Error().Err(err).Msg(sqlStmt)
					} else {
						if found {
							v := updateUserInfo(myuserinfo, "Qrcode", "")
							userinfocache.Set(token, v, cache.NoExpiration)
						}
					}
				} else {
					log.Info().Str("event", evt.Event).Msg("Login event")
				}
			}
		}

	} else {
		// Already logged in, just connect
		log.Info().Msg("Already logged in, just connect")
		err = client.Connect()
		if err != nil {
			panic(err)
		}
	}

	// Keep connected client live until disconnected/killed
	for {
		select {
		case <-killchannel[userID]:
			log.Info().Str("userid", userID).Msg("Received kill signal")
			client.Disconnect()
			clientManager.DeleteWhatsmeowClient(userID)
			clientManager.DeleteMyClient(userID)
			clientManager.DeleteHTTPClient(userID)
			sqlStmt := `UPDATE users SET qrcode='', connected=0 WHERE id=$1`
			_, err := s.db.Exec(sqlStmt, "", userID)
			if err != nil {
				log.Error().Err(err).Msg(sqlStmt)
			}
			return
		default:
			time.Sleep(1000 * time.Millisecond)
			//log.Info().Str("jid",textjid).Msg("Loop the loop")
		}
	}
}

func fileToBase64(filepath string) (string, string, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return "", "", err
	}
	mimeType := http.DetectContentType(data)
	return base64.StdEncoding.EncodeToString(data), mimeType, nil
}

func (mycli *MyClient) myEventHandler(rawEvt interface{}) {
	txtid := mycli.userID
	postmap := make(map[string]interface{})
	postmap["event"] = rawEvt
	dowebhook := 0
	path := ""

	switch evt := rawEvt.(type) {
	case *events.AppStateSyncComplete:
		if len(mycli.WAClient.Store.PushName) > 0 && evt.Name == appstate.WAPatchCriticalBlock {
			err := mycli.WAClient.SendPresence(types.PresenceAvailable)
			if err != nil {
				log.Warn().Err(err).Msg("Failed to send available presence")
			} else {
				log.Info().Msg("Marked self as available")
			}
		}
	case *events.Connected, *events.PushNameSetting:
		if len(mycli.WAClient.Store.PushName) == 0 {
			return
		}
		// Send presence available when connecting and when the pushname is changed.
		// This makes sure that outgoing messages always have the right pushname.
		err := mycli.WAClient.SendPresence(types.PresenceAvailable)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to send available presence")
		} else {
			log.Info().Msg("Marked self as available")
		}
		sqlStmt := `UPDATE users SET connected=1 WHERE id=$1`
		_, err = mycli.db.Exec(sqlStmt, mycli.userID)
		if err != nil {
			log.Error().Err(err).Msg(sqlStmt)
			return
		}
	case *events.PairSuccess:
		log.Info().Str("userid", mycli.userID).Str("token", mycli.token).Str("ID", evt.ID.String()).Str("BusinessName", evt.BusinessName).Str("Platform", evt.Platform).Msg("QR Pair Success")
		jid := evt.ID
		sqlStmt := `UPDATE users SET jid=$1 WHERE id=$2`
		_, err := mycli.db.Exec(sqlStmt, jid, mycli.userID)
		if err != nil {
			log.Error().Err(err).Msg(sqlStmt)
			return
		}

		myuserinfo, found := userinfocache.Get(mycli.token)
		if !found {
			log.Warn().Msg("No user info cached on pairing?")
		} else {
			txtid = myuserinfo.(Values).Get("Id")
			token := myuserinfo.(Values).Get("Token")
			v := updateUserInfo(myuserinfo, "Jid", fmt.Sprintf("%s", jid))
			userinfocache.Set(token, v, cache.NoExpiration)
			log.Info().Str("jid", jid.String()).Str("userid", txtid).Str("token", token).Msg("User information set")
		}
	case *events.StreamReplaced:
		log.Info().Msg("Received StreamReplaced event")
		return
	case *events.Message:
		postmap["type"] = "Message"
		dowebhook = 1
		metaParts := []string{fmt.Sprintf("pushname: %s", evt.Info.PushName), fmt.Sprintf("timestamp: %s", evt.Info.Timestamp)}
		if evt.Info.Type != "" {
			metaParts = append(metaParts, fmt.Sprintf("type: %s", evt.Info.Type))
		}
		if evt.Info.Category != "" {
			metaParts = append(metaParts, fmt.Sprintf("category: %s", evt.Info.Category))
		}
		if evt.IsViewOnce {
			metaParts = append(metaParts, "view once")
		}
		if evt.IsViewOnce {
			metaParts = append(metaParts, "ephemeral")
		}

		log.Info().Str("id", evt.Info.ID).Str("source", evt.Info.SourceString()).Str("parts", strings.Join(metaParts, ", ")).Msg("Message Received")

		if !*skipMedia {
			// try to get Image if any
			img := evt.Message.GetImageMessage()
			if img != nil {
				// Create a temporary directory in /tmp
				tmpDirectory := filepath.Join("/tmp", "user_"+txtid)
				errDir := os.MkdirAll(tmpDirectory, 0751)
				if errDir != nil {
					log.Error().Err(errDir).Msg("Could not create temporary directory")
					return
				}

				// Download the image
				data, err := mycli.WAClient.Download(context.Background(), img)
				if err != nil {
					log.Error().Err(err).Msg("Failed to download image")
					return
				}

				// Determine the file extension based on the MIME type
				exts, _ := mime.ExtensionsByType(img.GetMimetype())
				tmpPath := filepath.Join(tmpDirectory, evt.Info.ID+exts[0])

				// Write the image to the temporary file
				err = os.WriteFile(tmpPath, data, 0600)
				if err != nil {
					log.Error().Err(err).Msg("Failed to save image to temporary file")
					return
				}

				// Check if S3 is enabled for this user
				var s3Config struct {
					Enabled       bool   `db:"s3_enabled"`
					MediaDelivery string `db:"media_delivery"`
				}
				err = mycli.db.Get(&s3Config, "SELECT s3_enabled, media_delivery FROM users WHERE id = $1", txtid)
				if err != nil {
					log.Error().Err(err).Msg("Failed to get S3 config")
					s3Config.Enabled = false
					s3Config.MediaDelivery = "base64"
				}

				// Process S3 upload if enabled
				if s3Config.Enabled && (s3Config.MediaDelivery == "s3" || s3Config.MediaDelivery == "both") {
					// Get sender JID for inbox/outbox determination
					isIncoming := evt.Info.IsFromMe == false
					contactJID := evt.Info.Sender.String()
					if evt.Info.IsGroup {
						contactJID = evt.Info.Chat.String()
					}

					// Process S3 upload
					s3Data, err := GetS3Manager().ProcessMediaForS3(
						context.Background(),
						txtid,
						contactJID,
						evt.Info.ID,
						data,
						img.GetMimetype(),
						filepath.Base(tmpPath),
						isIncoming,
					)
					if err != nil {
						log.Error().Err(err).Msg("Failed to upload image to S3")
					} else {
						postmap["s3"] = s3Data
					}
				}

				// Convert the image to base64 if needed
				if s3Config.MediaDelivery == "base64" || s3Config.MediaDelivery == "both" {
					base64String, mimeType, err := fileToBase64(tmpPath)
					if err != nil {
						log.Error().Err(err).Msg("Failed to convert image to base64")
						return
					}

					// Add the base64 string and other details to the postmap
					postmap["base64"] = base64String
					postmap["mimeType"] = mimeType
					postmap["fileName"] = filepath.Base(tmpPath)
				}

				// Log the successful conversion
				log.Info().Str("path", tmpPath).Msg("Image processed")

				// Delete the temporary file
				err = os.Remove(tmpPath)
				if err != nil {
					log.Error().Err(err).Msg("Failed to delete temporary file")
				} else {
					log.Info().Str("path", tmpPath).Msg("Temporary file deleted")
				}
			}

			// try to get Audio if any
			audio := evt.Message.GetAudioMessage()
			if audio != nil {
				// Create a temporary directory in /tmp
				tmpDirectory := filepath.Join("/tmp", "user_"+txtid)
				errDir := os.MkdirAll(tmpDirectory, 0751)
				if errDir != nil {
					log.Error().Err(errDir).Msg("Could not create temporary directory")
					return
				}

				// Download the audio
				data, err := mycli.WAClient.Download(context.Background(), audio)
				if err != nil {
					log.Error().Err(err).Msg("Failed to download audio")
					return
				}

				// Determine the file extension based on the MIME type
				exts, _ := mime.ExtensionsByType(audio.GetMimetype())
				var ext string
				if len(exts) > 0 {
					ext = exts[0]
				} else {
					ext = ".ogg" // Default extension if MIME type is not recognized
				}
				tmpPath := filepath.Join(tmpDirectory, evt.Info.ID+ext)

				// Write the audio to the temporary file
				err = os.WriteFile(tmpPath, data, 0600)
				if err != nil {
					log.Error().Err(err).Msg("Failed to save audio to temporary file")
					return
				}

				// Check if S3 is enabled for this user
				var s3Config struct {
					Enabled       bool   `db:"s3_enabled"`
					MediaDelivery string `db:"media_delivery"`
				}
				err = mycli.db.Get(&s3Config, "SELECT s3_enabled, media_delivery FROM users WHERE id = $1", txtid)
				if err != nil {
					log.Error().Err(err).Msg("Failed to get S3 config")
					s3Config.Enabled = false
					s3Config.MediaDelivery = "base64"
				}

				// Process S3 upload if enabled
				if s3Config.Enabled && (s3Config.MediaDelivery == "s3" || s3Config.MediaDelivery == "both") {
					// Get sender JID for inbox/outbox determination
					isIncoming := evt.Info.IsFromMe == false
					contactJID := evt.Info.Sender.String()
					if evt.Info.IsGroup {
						contactJID = evt.Info.Chat.String()
					}

					// Process S3 upload
					s3Data, err := GetS3Manager().ProcessMediaForS3(
						context.Background(),
						txtid,
						contactJID,
						evt.Info.ID,
						data,
						audio.GetMimetype(),
						filepath.Base(tmpPath),
						isIncoming,
					)
					if err != nil {
						log.Error().Err(err).Msg("Failed to upload audio to S3")
					} else {
						postmap["s3"] = s3Data
					}
				}

				// Convert the audio to base64 if needed
				if s3Config.MediaDelivery == "base64" || s3Config.MediaDelivery == "both" {
					base64String, mimeType, err := fileToBase64(tmpPath)
					if err != nil {
						log.Error().Err(err).Msg("Failed to convert audio to base64")
						return
					}

					// Add the base64 string and other details to the postmap
					postmap["base64"] = base64String
					postmap["mimeType"] = mimeType
					postmap["fileName"] = filepath.Base(tmpPath)
				}

				// Log the successful conversion
				log.Info().Str("path", tmpPath).Msg("Audio processed")

				// Delete the temporary file
				err = os.Remove(tmpPath)
				if err != nil {
					log.Error().Err(err).Msg("Failed to delete temporary file")
				} else {
					log.Info().Str("path", tmpPath).Msg("Temporary file deleted")
				}
			}

			// try to get Document if any
			document := evt.Message.GetDocumentMessage()
			if document != nil {
				// Create a temporary directory in /tmp
				tmpDirectory := filepath.Join("/tmp", "user_"+txtid)
				errDir := os.MkdirAll(tmpDirectory, 0751)
				if errDir != nil {
					log.Error().Err(errDir).Msg("Could not create temporary directory")
					return
				}

				// Download the document
				data, err := mycli.WAClient.Download(context.Background(), document)
				if err != nil {
					log.Error().Err(err).Msg("Failed to download document")
					return
				}

				// Determine the file extension
				extension := ""
				exts, err := mime.ExtensionsByType(document.GetMimetype())
				if err == nil && len(exts) > 0 {
					extension = exts[0]
				} else {
					filename := document.FileName
					if filename != nil {
						extension = filepath.Ext(*filename)
					} else {
						extension = ".bin" // Default extension if no filename or MIME type is available
					}
				}
				tmpPath := filepath.Join(tmpDirectory, evt.Info.ID+extension)

				// Write the document to the temporary file
				err = os.WriteFile(tmpPath, data, 0600)
				if err != nil {
					log.Error().Err(err).Msg("Failed to save document to temporary file")
					return
				}

				// Check if S3 is enabled for this user
				var s3Config struct {
					Enabled       bool   `db:"s3_enabled"`
					MediaDelivery string `db:"media_delivery"`
				}
				err = mycli.db.Get(&s3Config, "SELECT s3_enabled, media_delivery FROM users WHERE id = $1", txtid)
				if err != nil {
					log.Error().Err(err).Msg("Failed to get S3 config")
					s3Config.Enabled = false
					s3Config.MediaDelivery = "base64"
				}

				// Process S3 upload if enabled
				if s3Config.Enabled && (s3Config.MediaDelivery == "s3" || s3Config.MediaDelivery == "both") {
					// Get sender JID for inbox/outbox determination
					isIncoming := evt.Info.IsFromMe == false
					contactJID := evt.Info.Sender.String()
					if evt.Info.IsGroup {
						contactJID = evt.Info.Chat.String()
					}

					// Process S3 upload
					s3Data, err := GetS3Manager().ProcessMediaForS3(
						context.Background(),
						txtid,
						contactJID,
						evt.Info.ID,
						data,
						document.GetMimetype(),
						filepath.Base(tmpPath),
						isIncoming,
					)
					if err != nil {
						log.Error().Err(err).Msg("Failed to upload document to S3")
					} else {
						postmap["s3"] = s3Data
					}
				}

				// Convert the document to base64 if needed
				if s3Config.MediaDelivery == "base64" || s3Config.MediaDelivery == "both" {
					base64String, mimeType, err := fileToBase64(tmpPath)
					if err != nil {
						log.Error().Err(err).Msg("Failed to convert document to base64")
						return
					}

					// Add the base64 string and other details to the postmap
					postmap["base64"] = base64String
					postmap["mimeType"] = mimeType
					postmap["fileName"] = filepath.Base(tmpPath)
				}

				// Log the successful conversion
				log.Info().Str("path", tmpPath).Msg("Document processed")

				// Delete the temporary file
				err = os.Remove(tmpPath)
				if err != nil {
					log.Error().Err(err).Msg("Failed to delete temporary file")
				} else {
					log.Info().Str("path", tmpPath).Msg("Temporary file deleted")
				}
			}

			// try to get Video if any
			video := evt.Message.GetVideoMessage()
			if video != nil {
				// Create a temporary directory in /tmp
				tmpDirectory := filepath.Join("/tmp", "user_"+txtid)
				errDir := os.MkdirAll(tmpDirectory, 0751)
				if errDir != nil {
					log.Error().Err(errDir).Msg("Could not create temporary directory")
					return
				}

				// Download the video
				data, err := mycli.WAClient.Download(context.Background(), video)
				if err != nil {
					log.Error().Err(err).Msg("Failed to download video")
					return
				}

				// Determine the file extension based on the MIME type
				exts, _ := mime.ExtensionsByType(video.GetMimetype())
				tmpPath := filepath.Join(tmpDirectory, evt.Info.ID+exts[0])

				// Write the video to the temporary file
				err = os.WriteFile(tmpPath, data, 0600)
				if err != nil {
					log.Error().Err(err).Msg("Failed to save video to temporary file")
					return
				}

				// Check if S3 is enabled for this user
				var s3Config struct {
					Enabled       bool   `db:"s3_enabled"`
					MediaDelivery string `db:"media_delivery"`
				}
				err = mycli.db.Get(&s3Config, "SELECT s3_enabled, media_delivery FROM users WHERE id = $1", txtid)
				if err != nil {
					log.Error().Err(err).Msg("Failed to get S3 config")
					s3Config.Enabled = false
					s3Config.MediaDelivery = "base64"
				}

				// Process S3 upload if enabled
				if s3Config.Enabled && (s3Config.MediaDelivery == "s3" || s3Config.MediaDelivery == "both") {
					// Get sender JID for inbox/outbox determination
					isIncoming := evt.Info.IsFromMe == false
					contactJID := evt.Info.Sender.String()
					if evt.Info.IsGroup {
						contactJID = evt.Info.Chat.String()
					}

					// Process S3 upload
					s3Data, err := GetS3Manager().ProcessMediaForS3(
						context.Background(),
						txtid,
						contactJID,
						evt.Info.ID,
						data,
						video.GetMimetype(),
						filepath.Base(tmpPath),
						isIncoming,
					)
					if err != nil {
						log.Error().Err(err).Msg("Failed to upload video to S3")
					} else {
						postmap["s3"] = s3Data
					}
				}

				// Convert the video to base64 if needed
				if s3Config.MediaDelivery == "base64" || s3Config.MediaDelivery == "both" {
					base64String, mimeType, err := fileToBase64(tmpPath)
					if err != nil {
						log.Error().Err(err).Msg("Failed to convert video to base64")
						return
					}

					// Add the base64 string and other details to the postmap
					postmap["base64"] = base64String
					postmap["mimeType"] = mimeType
					postmap["fileName"] = filepath.Base(tmpPath)
				}

				// Log the successful conversion
				log.Info().Str("path", tmpPath).Msg("Video processed")

				// Delete the temporary file
				err = os.Remove(tmpPath)
				if err != nil {
					log.Error().Err(err).Msg("Failed to delete temporary file")
				} else {
					log.Info().Str("path", tmpPath).Msg("Temporary file deleted")
				}
			}
		}

	case *events.Receipt:
		postmap["type"] = "ReadReceipt"
		dowebhook = 1
		//if evt.Type == events.ReceiptTypeRead || evt.Type == events.ReceiptTypeReadSelf {
		if evt.Type == types.ReceiptTypeRead || evt.Type == types.ReceiptTypeReadSelf {
			log.Info().Strs("id", evt.MessageIDs).Str("source", evt.SourceString()).Str("timestamp", fmt.Sprintf("%v", evt.Timestamp)).Msg("Message was read")
			//if evt.Type == events.ReceiptTypeRead {
			if evt.Type == types.ReceiptTypeRead {
				postmap["state"] = "Read"
			} else {
				postmap["state"] = "ReadSelf"
			}
			//} else if evt.Type == events.ReceiptTypeDelivered {
		} else if evt.Type == types.ReceiptTypeDelivered {
			postmap["state"] = "Delivered"
			log.Info().Str("id", evt.MessageIDs[0]).Str("source", evt.SourceString()).Str("timestamp", fmt.Sprintf("%v", evt.Timestamp)).Msg("Message delivered")
		} else {
			// Discard webhooks for inactive or other delivery types
			return
		}
	case *events.Presence:
		postmap["type"] = "Presence"
		dowebhook = 1
		if evt.Unavailable {
			postmap["state"] = "offline"
			if evt.LastSeen.IsZero() {
				log.Info().Str("from", evt.From.String()).Msg("User is now offline")
			} else {
				log.Info().Str("from", evt.From.String()).Str("lastSeen", fmt.Sprintf("%v", evt.LastSeen)).Msg("User is now offline")
			}
		} else {
			postmap["state"] = "online"
			log.Info().Str("from", evt.From.String()).Msg("User is now online")
		}
	case *events.HistorySync:
		postmap["type"] = "HistorySync"
		dowebhook = 1
	case *events.AppState:
		log.Info().Str("index", fmt.Sprintf("%+v", evt.Index)).Str("actionValue", fmt.Sprintf("%+v", evt.SyncActionValue)).Msg("App state event received")
	case *events.LoggedOut:
		log.Info().Str("reason", evt.Reason.String()).Msg("Logged out")
		killchannel[mycli.userID] <- true
		sqlStmt := `UPDATE users SET connected=0 WHERE id=$1`
		_, err := mycli.db.Exec(sqlStmt, mycli.userID)
		if err != nil {
			log.Error().Err(err).Msg(sqlStmt)
			return
		}
	case *events.ChatPresence:
		postmap["type"] = "ChatPresence"
		dowebhook = 1
		log.Info().Str("state", fmt.Sprintf("%s", evt.State)).Str("media", fmt.Sprintf("%s", evt.Media)).Str("chat", evt.MessageSource.Chat.String()).Str("sender", evt.MessageSource.Sender.String()).Msg("Chat Presence received")
	case *events.CallOffer:
		log.Info().Str("event", fmt.Sprintf("%+v", evt)).Msg("Got call offer")
	case *events.CallAccept:
		log.Info().Str("event", fmt.Sprintf("%+v", evt)).Msg("Got call accept")
	case *events.CallTerminate:
		log.Info().Str("event", fmt.Sprintf("%+v", evt)).Msg("Got call terminate")
	case *events.CallOfferNotice:
		log.Info().Str("event", fmt.Sprintf("%+v", evt)).Msg("Got call offer notice")
	case *events.CallRelayLatency:
		log.Info().Str("event", fmt.Sprintf("%+v", evt)).Msg("Got call relay latency")
	default:
		log.Warn().Str("event", fmt.Sprintf("%+v", evt)).Msg("Unhandled event")
	}

	if dowebhook == 1 {
		// call webhook
		webhookurl := ""
		myuserinfo, found := userinfocache.Get(mycli.token)
		if !found {
			log.Warn().Str("token", mycli.token).Msg("Could not call webhook as there is no user for this token")
		} else {
			webhookurl = myuserinfo.(Values).Get("Webhook")
		}

		// Get updated events from cache/database
		currentEvents := ""
		userinfo2, found2 := userinfocache.Get(mycli.token)
		if found2 {
			currentEvents = userinfo2.(Values).Get("Events")
		} else {
			// If not in cache, get from database
			var err error
			err = mycli.db.Get(&currentEvents, "SELECT events FROM users WHERE id=$1", mycli.userID)
			if err != nil {
				log.Warn().Err(err).Msg("Could not get events from DB")
			}
		}

		// Update client subscriptions if changed
		eventarray := strings.Split(currentEvents, ",")
		var subscribedEvents []string
		if len(eventarray) == 1 && eventarray[0] == "" {
			subscribedEvents = []string{}
		} else {
			for _, arg := range eventarray {
				arg = strings.TrimSpace(arg)
				if arg != "" && Find(supportedEventTypes, arg) {
					subscribedEvents = append(subscribedEvents, arg)
				}
			}
		}

		// Update the client subscriptions
		mycli.subscriptions = subscribedEvents

		// Log subscription details for debugging
		log.Debug().
			Str("userID", mycli.userID).
			Str("eventType", postmap["type"].(string)).
			Strs("subscribedEvents", subscribedEvents).
			Msg("Checking event subscription")

		// Check if the current event is in the subscriptions
		if !Find(subscribedEvents, postmap["type"].(string)) && !Find(subscribedEvents, "All") {
			log.Warn().
				Str("type", postmap["type"].(string)).
				Strs("subscribedEvents", subscribedEvents).
				Str("userID", mycli.userID).
				Msg("Skipping webhook. Not subscribed for this type")
			return
		}

		// Prepare webhook data
		jsonData, err := json.Marshal(postmap)
		if err != nil {
			log.Error().Err(err).Msg("Failed to marshal postmap to JSON")
			return
		}

		data := map[string]string{
			"jsonData": string(jsonData),
			"token":    mycli.token,
		}

		// Add this log
		log.Debug().Interface("webhookData", data).Msg("Data being sent to webhook")

		// Call user webhook if configured
		if webhookurl != "" {
			log.Info().Str("url", webhookurl).Msg("Calling user webhook")
			if path == "" {
				go callHook(webhookurl, data, mycli.userID)
			} else {
				// Create a channel to capture the error from the goroutine
				errChan := make(chan error, 1)
				go func() {
					err := callHookFile(webhookurl, data, mycli.userID, path)
					errChan <- err
				}()

				// Optionally handle the error from the channel (if needed)
				if err := <-errChan; err != nil {
					log.Error().Err(err).Msg("Error calling hook file")
				}
			}
		} else {
			log.Warn().Str("userid", mycli.userID).Msg("No webhook set for user")
		}

		// Get global webhook if configured
		if *globalWebhook != "" {
			log.Info().Str("url", *globalWebhook).Msg("Calling global webhook")
			// Add extra information for the global webhook
			globalData := map[string]string{
				"jsonData": string(jsonData),
				"token":    mycli.token,
				"userID":   mycli.userID,
			}
			go callHook(*globalWebhook, globalData, mycli.userID)
		}
	}
}
