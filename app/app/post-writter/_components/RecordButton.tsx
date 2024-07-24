'use client';

import { Mic, MicOff } from 'lucide-react';
import useMicrophone from '../../ideas/_components/useMicrophone';
import { Button } from '@/components/ui/button';
import { useCallback, useState } from 'react';
import { cn } from '@/lib/utils';
import { toast } from 'sonner';

type PrefersToRecordProps = {
    onRecord: (text: string) => void;
    text: string;
};

export function RecordButton({ onRecord, text }: PrefersToRecordProps) {
    const onMicAllowed = useCallback((isAllowed: boolean) => {
        toast(isAllowed ? 'Ya puedes grabarte!!' : 'Microphone is denied');
    }, []);
    const [isMicroAllowed, setIsMicroAllowed] = useState(false);
    const {
        startRecording,
        stopRecording,
        toggleRecording,
        isRecording,
        initMediaRecorder,
        error,
    } = useMicrophone({
        onMicAllowed,
        setSpeech: onRecord,
    });

    const handleToggleMicStatus = () => {
        if (!isMicroAllowed) {
            setIsMicroAllowed(true);
            initMediaRecorder();
            return;
        }
        if (isRecording) {
            stopRecording();
        } else {
            startRecording();
        }
    };

    return (
        <div>
            <Button
                className={cn(
                    `absolute top-1 right-1 flex justify-center items-center`,
                    isMicroAllowed
                        ? 'bg-green-500 hover:bg-green-500 bg-opacity-20'
                        : '',
                    isRecording ? 'bg-red-500 hover:bg-red-500' : ''
                )}
                variant={'secondary'}
                size={'icon'}
                type='button'
                onClick={handleToggleMicStatus}
            >
                {!isMicroAllowed ? <MicOff size={24} /> : <Mic size={24} />}
            </Button>
            {JSON.stringify(error)}
        </div>
    );
}
