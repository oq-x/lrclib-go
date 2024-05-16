package lrclib

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type SongData struct {
	ID           int     `json:"id"`
	TrackName    string  `json:"trackName"`
	ArtistName   string  `json:"artistName"`
	AlbumName    string  `json:"albumName"`
	Duration     float64 `json:"duration"`
	Instrumental bool    `json:"instrumental"`
	PlainLyrics  string  `json:"plainLyrics"`
	SyncedLyrics string  `json:"syncedLyrics"`
}

type SyncedLyric struct {
	At    time.Duration
	Text  string
	Index int
}

func FormatSyncedLyrics(lyrics []SyncedLyrics) string {
	var str string
	for i, lyric := range syncedLyrics {
		newline := ""
		if i != len(syncedLyrics)-1 {
			newline = "\n"
		}
		minutes := int(lyric.At.Minutes())
		seconds := lyric.At.Seconds()
		str += fmt.Sprintf("[%d:%02.2f] %s", minutes, seconds, lyric.Lyric) + newline
	}
	return str
}

func ParseSyncedLyrics(str string) []SyncedLyric {
	lines := strings.Split(str, "\n")
	syncedLyrics := make([]SyncedLyric, len(lines))
	for index, line := range lines {
		i := strings.Index(line, " ")
		if i == -1 {
			continue
		}
		stamp := line[:i]
		lyric := line[i:]

		stamp = stamp[1 : len(stamp)-1]
		sep := strings.Split(stamp, ":")
		if len(sep) != 2 {
			continue
		}
		minutes, err := strconv.ParseInt(sep[0], 10, 64)
		if err != nil {
			continue
		}
		seconds, err := strconv.ParseFloat(sep[1], 64)
		if err != nil {
			continue
		}

		duration := (time.Duration(minutes) * time.Minute) + time.Duration(seconds*float64(time.Second))
		syncedLyrics[index] = SyncedLyric{
			At:    duration,
			Text:  lyric,
			Index: index,
		}
	}
	return syncedLyrics
}

func SearchSong(query, trackName, artistName, albumName string) ([]SongData, error) {
	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("https://lrclib.net/api/search?q=%strack_name=%s&artist_name=%s&album_name=%s",
		url.QueryEscape(query),
		url.QueryEscape(trackName),
		url.QueryEscape(artistName),
		url.QueryEscape(albumName),
	), nil)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("not found song")
	}
	var data []SongData
	err = json.NewDecoder(res.Body).Decode(&data)

	return data, err
}

func GetSong(trackName, artistName, albumName string, duration time.Duration, cached bool) (SongData, error) {
	c := ""
	if cached {
		c = "-cached"
	}
	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("https://lrclib.net/api/get%s?track_name=%s&artist_name=%s&album_name=%s&duration=%d",
		c,
		url.QueryEscape(trackName),
		url.QueryEscape(artistName),
		url.QueryEscape(albumName),
		duration/time.Second,
	), nil)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return SongData{}, err
	}
	if res.StatusCode == http.StatusNotFound {
		return SongData{}, fmt.Errorf("not found song")
	}
	var data SongData
	err = json.NewDecoder(res.Body).Decode(&data)

	return data, err
}

func GetSongByID(id string) (SongData, error) {
	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("https://lrclib.net/api/get/%s",
		url.QueryEscape(id),
	), nil)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return SongData{}, err
	}
	if res.StatusCode == http.StatusNotFound {
		return SongData{}, fmt.Errorf("not found song")
	}
	var data SongData
	err = json.NewDecoder(res.Body).Decode(&data)

	return data, err
}

func PublishSong(song SongData) error {
	body, err := json.Marshal(song)
	if err != nil {
		return err
	}

	token, err := NewPublishToken()
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, "https://lrclib.net/api/publish", bytes.NewReader(body))
	req.Header.Set("X-Publish-Token", token)
	if err != nil {
		return err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	if res.StatusCode == http.StatusCreated {
		return nil
	}
	var failed PublishError
	err = json.NewDecoder(res.Body).Decode(&failed)
	if err != nil {
		return err
	}
	return failed
}

type PublishError struct {
	Code    int    `json:"code"`
	Name    string `json:"name"`
	Message string `json:"message"`
}

func (p PublishError) Error() string {
	return fmt.Sprintf("%s (code %d): %s", p.Name, p.Code, p.Message)
}

func NewPublishToken() (string, error) {
	req, err := http.NewRequest(http.MethodPost, "https://lrclib.net/api/request-challenge", nil)
	if err != nil {
		return "", err
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}

	var response struct {
		Prefix string `json:"prefix"`
		Target string `json:"target"`
	}
	err = json.NewDecoder(res.Body).Decode(&response)
	if err != nil {
		return "", err
	}

	nonce := solveChallenge(response.Prefix, response.Target)

	return fmt.Sprintf("{%s}:{%s}", response.Prefix, nonce), nil
}

func verifyNonce(result []byte, target []byte) bool {
	if len(result) != len(target) {
		return false
	}

	for i := 0; i < len(result); i++ {
		if result[i] > target[i] {
			return false
		} else if result[i] < target[i] {
			break
		}
	}

	return true
}

func solveChallenge(prefix string, targetHex string) string {
	nonce := 0
	target, _ := hex.DecodeString(targetHex)

	for {
		input := prefix + strconv.Itoa(nonce)
		hashed := sha256.Sum256([]byte(input))

		if verifyNonce(hashed[:], target) {
			break
		} else {
			nonce++
		}
	}

	return strconv.Itoa(nonce)
}
