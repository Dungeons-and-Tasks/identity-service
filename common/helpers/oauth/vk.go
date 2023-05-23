package oauth

import (
	"identity/common/helpers/apperrors"
	"identity/config"
	"net/url"
	"strconv"
	"strings"

	"github.com/go-resty/resty/v2"
)

type vkToken struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   uint   `json:"expires_in"`
	UserId      uint   `json:"user_id"`
	Email       string `json:"email"`
}

type vkUserInfo struct {
	Id        string `json:"id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	HasPhoto  int    `json:"has_photo"` // 1 or 0
	PhotoMax  string `json:"photo_max"`
}

func GetVKAuthURI(cfg *config.Config) (string, error) {
	var u, err = url.Parse(cfg.VK_AUTH_URI)
	if err != nil {
		return "", apperrors.NewInternal("failed parse vk auth uri")
	}
	v := url.Values{}
	v.Set("scope", strings.Join(cfg.VK_SCOPE, " "))
	v.Set("display", "page")
	v.Set("response_type", "code")
	v.Set("redirect_uri", cfg.VK_REDIRECT_URI)
	v.Set("client_id", cfg.VK_CLIENT_ID)
	u.RawQuery = v.Encode()
	return u.String(), nil
}

func getVKToken(cfg *config.Config, code string) (*vkToken, error) {
	client := resty.New()
	var res vkToken
	var req_err error
	_, err := client.R().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		SetFormData(map[string]string{
			"client_id":     cfg.VK_CLIENT_ID,
			"client_secret": cfg.VK_CLIENT_SECRET,
			"code":          code,
			"redirect_uri":  cfg.VK_REDIRECT_URI,
		}).
		SetError(&req_err).
		SetResult(&res).
		Post(cfg.VK_TOKEN_URI)
	if err != nil {
		return nil, apperrors.NewInternal(err.Error())
	} else if req_err != nil {
		return nil, apperrors.NewBadGateway(req_err.Error())
	}
	return &res, nil
}

func GetVKUserInfo(cfg *config.Config, code string) (*OAuthUser, error) {
	tokens, err := getVKToken(cfg, code)
	if err != nil {
		return nil, err
	}

	client := resty.New()
	var res vkUserInfo
	var req_err error
	_, err = client.R().
		SetHeader("Authorization", "Bearer "+tokens.AccessToken).
		SetError(&req_err).
		SetResult(&res).
		SetQueryParams(map[string]string{
			"user_ids":  strconv.FormatUint(uint64(tokens.UserId), 10),
			"fields":    "has_photo,photo_max",
			"name_case": "nom",
		}).
		Get(cfg.VK_USER_INFO_URI)
	if err != nil {
		return nil, apperrors.NewInternal(err.Error())
	} else if req_err != nil {
		return nil, apperrors.NewBadGateway(req_err.Error())
	}

	oauthUser := &OAuthUser{
		Id:    res.Id,
		Name:  res.FirstName,
		Email: tokens.Email,
	}

	if res.HasPhoto == 1 {
		oauthUser.Picture = res.PhotoMax
	}

	return oauthUser, nil
}
