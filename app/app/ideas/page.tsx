'use client';

import { useEffect } from 'react';
import useAudioRecorder from './_components/useAudioRecorder';
import { Button } from '@/components/ui/button';
import { createWebmFile } from '@/app/_actions/writter-actions';

export default function IdeasPage() {
    const {
        startRecording,
        stopRecording,
        togglePauseResume,
        recordingBlob,
        isRecording,
        isPaused,
        recordingTime,
        mediaRecorder,
    } = useAudioRecorder();

    useEffect(() => {
        if (!recordingBlob) return;
        const formData = new FormData();
        formData.append('audio', recordingBlob, 'recording.webm');

        const fn = async () => await createWebmFile(formData);
        fn();

        // recordingBlob will be present at this point after 'stopRecording' has been called
    }, [recordingBlob]);

    return (
        <div>
            <Button onClick={startRecording}>Start Recording</Button>
            <Button onClick={stopRecording}>Stop Recording</Button>
            {/* Status */}
            {isRecording && <p>Recording...</p>}
        </div>
    );
}
