package deovr

import (
	"time"

	"github.com/stashapp/stash/pkg/api/urlbuilders"
	"github.com/stashapp/stash/pkg/models"
)

type VideoSource struct {
	Resolution int64  `json:"resolution,omitempty"`
	URL        string `json:"url,omitempty"`
}

type Encoding struct {
	Name         string        `json:"name,omitempty"`
	VideoSources []VideoSource `json:"videoSources,omitempty"`
}

type Scene struct {
	Encodings     []Encoding `json:"encodings,omitempty"`
	Title         string     `json:"title,omitempty"`
	ID            int        `json:"id,omitempty"`
	Is3D          bool       `json:"is3d,omitempty"`
	Authenticated int        `json:"authenticated,omitempty"`
}

type LibraryItem struct {
	Title        string `json:"title,omitempty"`
	ThumbnailUrl string `json:"thumbnailUrl,omitempty"`
	VideoUrl     string `json:"video_url,omitempty"`
	videoLength  int    `json:"videoLength,omitempty"`
}

type Library struct {
	Name string        `json:"name,omitempty"`
	List []LibraryItem `json:"list,omitempty"`
}

type DeoVRPayload struct {
	Scenes     []Library `json:"scenes,omitempty"`
	Authorized string    `json:"authorized,omitempty"`
}

func ToDeoVRJSON(baseURL string, token string, scene *models.Scene) Scene {
	builder := urlbuilders.NewSceneURLBuilder(baseURL, scene.ID)

	return Scene{
		Title: scene.Title.String,
		ID:    scene.ID,
		Encodings: []Encoding{
			Encoding{
				Name: scene.VideoCodec.String,
				VideoSources: []VideoSource{
					VideoSource{
						Resolution: scene.Height.Int64,
						URL:        builder.GetStreamURL() + "?token=" + token,
					},
				},
			},
		},
	}
}

func LibraryToDeoVRJSON(baseURL string, token string, scenes []*models.Scene) DeoVRPayload {

	listItems := []LibraryItem{}

	for _, scene := range scenes {
		duration := float64(1.3)
		if scene.Duration.Valid {
			duration = scene.Duration.Float64
		}

		builder := urlbuilders.NewSceneURLBuilder(baseURL, scene.ID)

		listItems = append(listItems, LibraryItem{
			Title:        scene.Title.String,
			ThumbnailUrl: builder.GetScreenshotURL(time.Unix(int64(duration/2), 0)) + "&token=" + token,
			VideoUrl:     builder.GetDeoVRURL(),
		})
	}

	return DeoVRPayload{
		Authorized: "1",
		Scenes: []Library{
			Library{
				Name: "VR Scenes",
				List: listItems,
			},
		},
	}
}
