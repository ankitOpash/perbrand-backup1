'use client';

import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Separator } from '@/components/ui/separator';
import { Skeleton } from '@/components/ui/skeleton';
import { Textarea } from '@/components/ui/textarea';
import {
    Tooltip,
    TooltipContent,
    TooltipProvider,
    TooltipTrigger,
} from '@/components/ui/tooltip';
import { cn } from '@/lib/utils';
import { Edit, GalleryHorizontal, LucideIcon, Save } from 'lucide-react';
import { useContext, useState } from 'react';
import { PostWritterContext } from './PostWritterProvider';
import { useSession } from 'next-auth/react';
import { Pure } from '@/types/types';
import { LinkedinPost } from '@prisma/client';
import {
    createLinkedinPost,
    testingServer,
} from '@/app/_actions/writter-actions';

type GeneratedPostProps = {
    className?: string;
};

type Status = 'idle' | 'loading' | 'success' | 'error';

export const PostWritterResult = ({ className }: GeneratedPostProps) => {
    const { data } = useSession();

    const [status, setStatus] = useState<Status>('idle');
    const { post } = useContext(PostWritterContext);

    if (status === 'loading')
        return (
            <div className='flex-1 h-full w-full'>
                <Skeleton className='h-full w-full' />
            </div>
        );
    return (
        <div className={cn(``, className)}>
            <Label>Post generado</Label>
            <div className='border border-muted p-2 space-y-2'>
                <Textarea
                    rows={20}
                    className='border-none resize-none'
                    value={post}
                    readOnly
                />

                <div className='flex gap-2'>
                    <PostActionButton
                        icon={Save}
                        label='Guardar post'
                        onClick={async () => {
                            console.log('data', data?.user?.email!);
                            await createLinkedinPost(post);
                        }}
                    />
                    <PostActionButton icon={Edit} label='Editar post' />
                    <PostActionButton
                        icon={GalleryHorizontal}
                        label='Crear carrusel'
                    />
                </div>
            </div>
        </div>
    );
};

type PostActionButtonProps = {
    label?: string;
    className?: string;
    icon: LucideIcon;
    onClick?: () => void;
};

export const PostActionButton = ({
    icon: Icon,
    className,
    label,
    onClick,
}: PostActionButtonProps) => {
    return (
        <TooltipProvider>
            <Tooltip delayDuration={100}>
                <TooltipTrigger asChild className={className}>
                    <Button
                        onClick={onClick}
                        className='flex-1 rounded-full bg-muted text-primary/50
                    hover:bg-primary/10
                    '
                    >
                        <Icon />
                    </Button>
                </TooltipTrigger>
                <TooltipContent>{label}</TooltipContent>
            </Tooltip>
        </TooltipProvider>
    );
};
