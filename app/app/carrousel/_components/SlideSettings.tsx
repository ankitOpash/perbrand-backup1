import { Switch } from '@/components/ui/switch';
import { Textarea } from '@/components/ui/textarea';
import { Label } from '@radix-ui/react-label';
import { TSlide } from '../page';
import { cn } from '@/lib/utils';
import { Input } from '@/components/ui/input';
import { useContext } from 'react';
import { CarouselContext } from './ContextProvider';
import {
    ArrowLeft,
    ArrowLeftIcon,
    ArrowRight,
    ArrowRightIcon,
    Delete,
    MoveRight,
    MoveRightIcon,
    Plus,
    Trash,
    Trash2,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Separator } from '@/components/ui/separator';
import ContentEditable from 'react-contenteditable';

type SlideSettingsProps = {
    isActive?: boolean;
    className?: string;
    slide: TSlide;
};
export function SlideSettings({
    isActive = false,
    className,
    slide,
    ...slideProps
}: SlideSettingsProps) {
    const {
        editTitle,
        editTagline,
        editDescription,
        nextSlide,
        previousSlide,
        toggleSlideHasTitle,
        toggleSlideHasParagraph,
        toggleSlideHasTagline,
        carousel,
        toggleShowSwipeLabel,
    } = useContext(CarouselContext);

    if (!isActive) return null;
    return (
        <div
            className={cn(
                `flex flex-col p-4 gap-4 border bg-background rounded-md rounded-tr-none rounded-tl-none relative group`,
                className
            )}
        >
            <SlideActions />
            <Separator />
            <Button
                variant={'ghost'}
                className='absolute top-1/2 right-0 translate-x-[100%] opacity-0 group-hover:opacity-100 transition-opacity'
                onClick={nextSlide}
            >
                <ArrowRightIcon />
            </Button>
            <Button
                variant={'ghost'}
                className='absolute top-1/2 left-0 -translate-x-[100%] opacity-0 group-hover:opacity-100 transition-opacity'
                onClick={previousSlide}
            >
                <ArrowLeftIcon />
            </Button>
            <h2>Slide portada</h2>
            <div>
                <Switch
                    id='title'
                    checked={slide.title.isShown}
                    onCheckedChange={toggleSlideHasTitle}
                />
                <Label htmlFor='title'>Título</Label>
                {/* <ContentEditable
                    onChange={(e) => editTitle(e.target.value)}
                    html={slide.title!}
                    tagName='p'
                    className='border rounded-md p-2'
                /> */}
            </div>
            <div>
                <Switch
                    id='tagline'
                    checked={slide.tagline.isShown}
                    onCheckedChange={toggleSlideHasTagline}
                />
                <Label htmlFor='tagline'>Tagline</Label>
                {/* <Input
                    id='tagline'
                    value={slide.tagline!}
                    onChange={(e) => editTagline(e.target.value)}
                /> */}
            </div>
            <div>
                <Label htmlFor='paragraph'>Párrafo 1</Label>
                <Switch
                    id='tagline'
                    checked={slide.paragraphs[0].isShown}
                    onCheckedChange={toggleSlideHasParagraph}
                />
                {/* <Textarea
                    id='paragraph'
                    className='resize-none'
                    value={slide.description!}
                    onChange={(e) => editDescription(e.target.value)}
                /> */}
            </div>
            <div>
                <Label htmlFor='paragraph'>Etiqueta desliza</Label>
                <Switch
                    id='tagline'
                    checked={carousel.settings.showSwipeLabel}
                    onCheckedChange={toggleShowSwipeLabel}
                />
            </div>
        </div>
    );
}

export const SlideActions = () => {
    const {
        addSlideToRight,
        moveCurrentSlideToLeft,
        moveCurrentSlideToRight,
        deleteCurrentSlide,
        currentSlide,
        carousel,
    } = useContext(CarouselContext);

    const isLastSlide = currentSlide === carousel.slides.length - 1;
    const isFirstSlide = currentSlide === 0;

    return (
        <div className='flex gap-2 text-xs w-full'>
            <Button
                disabled={isFirstSlide}
                variant={'secondary'}
                size={'sm'}
                className='mr-auto'
                onClick={moveCurrentSlideToLeft}
            >
                <ArrowLeft className='h-4 w-4' />
                Mover
            </Button>
            <Button
                variant={'secondary'}
                size={'sm'}
                className='flex gap-1'
                onClick={deleteCurrentSlide}
            >
                <Trash2 className='h-4 w-4' />
            </Button>
            <Button
                variant={'secondary'}
                size={'sm'}
                className='mr-auto'
                onClick={addSlideToRight}
            >
                <Plus className='h-4 w-4' />
            </Button>
            <Button
                disabled={isLastSlide}
                variant={'secondary'}
                size={'sm'}
                className=''
                onClick={moveCurrentSlideToRight}
            >
                Mover
                <ArrowRightIcon />
            </Button>
        </div>
    );
};
