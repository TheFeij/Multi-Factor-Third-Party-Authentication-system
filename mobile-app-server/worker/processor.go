package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hibiken/asynq"
	"github.com/rs/zerolog/log"
	"go.mongodb.org/mongo-driver/mongo"
	"mobile-app-server/db"
	"mobile-app-server/email"
)

const (
	CriticalQueue = "critical"
	DefaultQueue  = "default"
)

type RedisTaskProcessor struct {
	Server      *asynq.Server
	Store       *db.Store
	EmailSender *email.EmailSender
}

func NewRedisTaskProcessor(opt *asynq.RedisClientOpt, store *db.Store, emailSender *email.EmailSender) *RedisTaskProcessor {
	server := asynq.NewServer(opt, asynq.Config{
		Queues: map[string]int{
			CriticalQueue: 10,
			DefaultQueue:  5,
		},
		ErrorHandler: asynq.ErrorHandlerFunc(func(ctx context.Context, task *asynq.Task, err error) {
			log.Error().Err(err).Str("type", task.Type()).Str("payload", string(task.Payload())).Msg("process task failed")
		}),
		Logger: NewLogger(),
	})

	return &RedisTaskProcessor{
		Server:      server,
		Store:       store,
		EmailSender: emailSender,
	}
}

func (p *RedisTaskProcessor) ProcessSendVerificationEmail(ctx context.Context, task *asynq.Task) error {
	var payload *SendVerificationEmailPayload
	if err := json.Unmarshal(task.Payload(), &payload); err != nil {
		return fmt.Errorf("failed to unmarshal payload: %w", asynq.SkipRetry)
	}

	tempUser, err := p.Store.GetTempUser(payload.ID)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return fmt.Errorf("user does not exists: %w", asynq.SkipRetry)
		}
		return fmt.Errorf("failed to get user from database: %w", err)
	}

	log.Info().Msg(fmt.Sprintf("sending verfication email to %v", tempUser.Email))

	content := fmt.Sprintf(`
		Hello %s,<br/>
		Thank You For Registering With Us!<br/>
		Here Is You Verification Code: %s
	`, tempUser.Username, tempUser.SecretCode)
	to := []string{tempUser.Email}
	err = p.EmailSender.SendEmail("Welcome To Authenticator", content, to, nil, nil, nil)
	if err != nil {
		return err
	}

	log.Info().Msg(fmt.Sprintf("verification email was sent to %v successfully", tempUser.Email))
	return nil
}

func (p *RedisTaskProcessor) Start() error {
	mux := asynq.NewServeMux()

	mux.HandleFunc(TaskSendVerificationEmail, p.ProcessSendVerificationEmail)

	return p.Server.Start(mux)
}
