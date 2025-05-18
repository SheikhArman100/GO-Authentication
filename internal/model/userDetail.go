package model

import (
	"time"
)

// UserDetail model
type UserDetail struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Address   string    `gorm:"type:varchar(255)" json:"address"`
	City      string    `gorm:"type:varchar(100)" json:"city"`
	Road      string    `gorm:"type:varchar(100)" json:"road"`
	UserID    uint      `gorm:"unique;not null" json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Relations
	User          User           `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"user,omitempty"`
	Image         *Image         `gorm:"foreignKey:UserDetailID;constraint:OnDelete:CASCADE" json:"image,omitempty"`
	SocialProfile *SocialProfile `gorm:"foreignKey:UserDetailID;constraint:OnDelete:CASCADE" json:"social_profile,omitempty"`
}

// TableName overrides the table name for UserDetail
func (UserDetail) TableName() string {
	return "userDetails"
}
