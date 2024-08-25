package parse

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"path/filepath"

	"github.com/yapingcat/gomedia/go-mp4"
	"github.com/yapingcat/gomedia/go-mpeg2"
)

func processTsFile(path string, muxer *mp4.Movmuxer, hasAudio *bool, hasVideo *bool, atid *uint32, vtid *uint32) error {
	tsFile, err := os.Open(path)
	if err != nil {
		return err
	}
	defer tsFile.Close()
	var frameError error
	demuxer := mpeg2.NewTSDemuxer()
	demuxer.OnFrame = func(cid mpeg2.TS_STREAM_TYPE, frame []byte, pts uint64, dts uint64) {
		if cid == mpeg2.TS_STREAM_H264 || cid == mpeg2.TS_STREAM_H265 {
			if !*hasVideo {
				switch cid {
				case mpeg2.TS_STREAM_H264:
					*vtid = muxer.AddVideoTrack(mp4.MP4_CODEC_H264)
				case mpeg2.TS_STREAM_H265:
					*vtid = muxer.AddVideoTrack(mp4.MP4_CODEC_H265)
				}
				*hasVideo = true
			}
			err := muxer.Write(*vtid, frame, uint64(pts), uint64(dts))
			if err != nil {
				frameError = err
				return
			}
		} else if cid == mpeg2.TS_STREAM_AAC {
			if !*hasAudio {
				*atid = muxer.AddAudioTrack(mp4.MP4_CODEC_AAC)
				*hasAudio = true
			}
			err := muxer.Write(*atid, frame, uint64(pts), uint64(dts))
			if err != nil {
				frameError = err
				return
			}
		} else if cid == mpeg2.TS_STREAM_AUDIO_MPEG1 || cid == mpeg2.TS_STREAM_AUDIO_MPEG2 {
			if !*hasAudio {
				*atid = muxer.AddAudioTrack(mp4.MP4_CODEC_MP3)
				*hasAudio = true
			}
			err := muxer.Write(*atid, frame, uint64(pts), uint64(dts))
			if err != nil {
				frameError = err
				return
			}
		}
	}
	if frameError != nil {
		return frameError
	}

	buf, err := io.ReadAll(tsFile)
	if err != nil {
		return err
	}
	err = demuxer.Input(bytes.NewReader(buf))
	if err != nil {
		return err
	}
	return nil
}

func MergeTs(downloadDir string) (r string, e error) {
	mvName := downloadDir + ".mp4"
	outMv, err := os.Create(mvName)
	if err != nil {
		return "", err
	}
	defer outMv.Close()

	muxer, err := mp4.CreateMp4Muxer(outMv)
	if err != nil {
		return "", err
	}

	defer func() {
		if err := recover(); err != nil {
			// fmt.Printf("第三方包调用失败: %v\n", err)
			tsErr := mergeToTs(outMv, downloadDir)
			if tsErr != nil {
				e = tsErr
				return
			}
			r = mvName
		}
	}()

	hasAudio := false
	hasVideo := false
	var atid uint32 = 0
	var vtid uint32 = 0

	mp4Err := filepath.Walk(downloadDir, func(path string, f os.FileInfo, err error) error {
		if f == nil {
			return err
		}
		if f.IsDir() || filepath.Ext(path) != ".ts" {
			return nil
		}
		errs := processTsFile(path, muxer, &hasAudio, &hasVideo, &atid, &vtid)
		if errs != nil {
			return errs
		}
		return nil
	})

	if mp4Err != nil {
		tsErr := mergeToTs(outMv, downloadDir)
		if tsErr != nil {
			return "", tsErr
		}
		return mvName, nil
	}

	err = muxer.WriteTrailer()
	if err != nil {
		return "", err
	}

	return mvName, nil
}

func mergeToTs(outMv *os.File, downloadDir string) error {
	writer := bufio.NewWriter(outMv)
	err := filepath.Walk(downloadDir, func(path string, f os.FileInfo, err error) error {
		if f == nil {
			return err
		}
		if f.IsDir() || filepath.Ext(path) != ".ts" {
			return nil
		}
		bytes, _ := os.ReadFile(path)
		_, err = writer.Write(bytes)
		return err
	})
	if err != nil {
		return err
	}
	_ = writer.Flush()
	return nil
}
