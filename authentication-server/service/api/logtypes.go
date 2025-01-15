package api

import (
	"authentication-server/service/db"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
)

type AppApproveRequestsLog struct {
	ID         primitive.ObjectID `json:"id,omitempty"`
	Username   string             `json:"username,omitempty"`
	DeviceInfo string             `json:"device_info,omitempty"`
	IP         string             `json:"ip,omitempty"`
	Time       time.Time          `json:"time"`
	Approved   bool               `json:"approved,omitempty"`
}

func ConvertAppApproveRequestsLogToLog(appLog *AppApproveRequestsLog) db.Log {
	return db.Log{
		Type:       string(db.LoginSecondStepAppApprove),
		Username:   appLog.Username,
		DeviceInfo: appLog.DeviceInfo,
		IP:         appLog.IP,
		Approved:   appLog.Approved,
		CreatedAt:  appLog.Time,
	}
}

func ConvertLogToAppApproveRequestsLog(log *db.Log) AppApproveRequestsLog {
	return AppApproveRequestsLog{
		ID:         log.ID,
		Username:   log.Username,
		DeviceInfo: log.DeviceInfo,
		IP:         log.IP,
		Time:       log.CreatedAt,
		Approved:   log.Approved,
	}
}
