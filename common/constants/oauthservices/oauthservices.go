package oauthservices

import "identity/models"

var (
	Google = models.OAuthService{
		ID:    1,
		Title: "google",
	}
	VK = models.OAuthService{
		ID:    2,
		Title: "vk",
	}
	GITHUB = models.OAuthService{
		ID:    3,
		Title: "github",
	}
	APPLE = models.OAuthService{
		ID:    4,
		Title: "apple",
	}
	OAuthServices = []models.OAuthService{
		Google,
		VK,
		GITHUB,
		APPLE,
	}
	OAuthServiceMap = map[string]uint{
		Google.Title: Google.ID,
		VK.Title:     VK.ID,
		GITHUB.Title: GITHUB.ID,
		APPLE.Title:  APPLE.ID,
	}
)
