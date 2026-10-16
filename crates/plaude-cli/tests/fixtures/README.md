# Generated audio fixtures

`pro-multiplexed-silence.ogg` is120ms synthetic silence encoded with ffmpeg/libopus,
with an independently CRC-encoded non-audio Ogg logical stream interleaved after
the OpusHead page. No real recording or user metadata is included.

`pro-offset-silence.ogg` is1.2seconds synthetic silence with audio-page granules
shifted by960samples and page CRCs recomputed. It covers nonzero initial granules
without depending on a real Pro recording.
