package worker

import (
	"Third-Party-Multi-Factor-Authentication-System/db"
	"Third-Party-Multi-Factor-Authentication-System/email"
	"Third-Party-Multi-Factor-Authentication-System/util"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hibiken/asynq"
	"github.com/rs/zerolog/log"
	"go.mongodb.org/mongo-driver/mongo"
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

	user, err := p.Store.GetUserByUsername(payload.Username)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return fmt.Errorf("user does not exists: %w", asynq.SkipRetry)
		}
		return fmt.Errorf("failed to get user from database: %w", err)
	}

	log.Info().Msg(fmt.Sprintf("sending verfication email to %v", user.Email))
	verifyEmail := &db.VerifyEmails{
		Username:   user.Username,
		Email:      user.Email,
		SecretCode: util.RandomString(16, util.ALL),
	}
	err = p.Store.InsertVerifyEmail(verifyEmail)
	if err != nil {
		return err
	}

	verifyUrl := fmt.Sprintf("api:8080?id=%s&secret_code=%s", verifyEmail.ID, verifyEmail.SecretCode)
	content := fmt.Sprintf(`
		Hello %s,<br/>
		Thank You For Registering With Us!<br/>
		Please <a href="%s">Click Here</a> To Verfiy Your Account
	`, user.Username, verifyUrl)
	to := []string{user.Email}
	err = p.EmailSender.SendEmail("Welcome To Authenticator", content, to, nil, nil, nil)
	if err != nil {
		return err
	}

	log.Info().Msg(fmt.Sprintf("verification email was sent to %v successfully", user.Email))
	return nil
}

func (p *RedisTaskProcessor) Start() error {
	mux := asynq.NewServeMux()

	mux.HandleFunc(TaskSendVerificationEmail, p.ProcessSendVerificationEmail)

	return p.Server.Start(mux)
}
