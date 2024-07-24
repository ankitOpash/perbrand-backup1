import { cn } from '@/lib/utils';
import { ArrowLeft, ArrowRight } from 'lucide-react';
import { useContext, useEffect, useRef } from 'react';
import { CarouselContext } from './ContextProvider';
import { SlideSettings } from './SlideSettings';
import { Slide } from './Slide';
import { TSlide } from '../page';
import { ASPECT_RATIOS_MAP } from './const';
// Whitelisting the classes:
type keys = keyof typeof translateClasses;
const translateClasses = {
    [100]: '-translate-x-[100%]',
    200: '-translate-x-[200%]',
    300: '-translate-x-[300%]',
    400: '-translate-x-[400%]',
    500: '-translate-x-[500%]',
    600: '-translate-x-[600%]',
} as const;

export const CarouselWorkbench = () => {
    const { currentSlide, nextSlide, previousSlide, carousel } =
        useContext(CarouselContext);
    return (
        <div className='not-sidebar basis-0 grow-[999] min-w-[60%] border-0 border-blue-500 p-2 bg-slate-100/50 bg-[url("/images/decoration/patterns/grid.svg")] flex flex-col gap-2 relative'>
            <div className='flex justify-center gap-4 w-full items-center text-sm mt-2'>
                <ArrowLeft
                    size={20}
                    onClick={previousSlide}
                    className='bg-muted p-1 rounded-full hover:cursor-pointer'
                />
                Slide {currentSlide + 1} / {carousel.slides.length}
                <ArrowRight
                    onClick={nextSlide}
                    size={20}
                    className='bg-muted p-1 rounded-full hover:cursor-pointer'
                />
            </div>
            <div className='carousel flex overflow-hidden md:pl-8 lg:pl-56 2xl:pl-96'>
                {carousel.slides.map((slide, index) => (
                    <SlideWithSettings
                        slide={slide}
                        key={index}
                        isActive={currentSlide === index}
                        slideNumber={index}
                        className={`${translateClasses[(100 * currentSlide) as keys]} transition-transform duration-300`}
                    />
                ))}
            </div>
        </div>
    );
};

type SlideWithSettingsProps = {
    className?: string;
    isActive: boolean;
    slide: TSlide;
    slideNumber: number;
};

const SlideWithSettings = ({
    className,
    isActive,
    slide,
    slideNumber,
}: SlideWithSettingsProps) => {
    const {
        carousel: {
            author: { handle, name, pictureUrl },
            settings: {
                aspectRatio,
                alternateColors,
                backgroundPattern,
                colorPalette,
                fontPalette,
                showAuthor,
                showCounter,
                showSwipeLabel,
            },
        },
        arrayOfRefs,
        setCurrentSlideTo,
        currentSlide,
        addRef,
    } = useContext(CarouselContext);
    const slideRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        console.log('adding a ref');
        addRef(slideRef, slideNumber);
    }, [addRef, slideNumber]);

    // console.log('refs from SlideWithSettings', slidesRef);

    return (
        <div
            className={cn(
                `shrink-0 isolate`,
                className,
                isActive ? 'z-10' : 'z-0'
            )}
        >
            <div className='border-r border-dashed'>
                <Slide
                    isActive={isActive}
                    setIsActive={() => {
                        setCurrentSlideTo(slideNumber);
                    }}
                    slide={slide}
                    slideNumber={slideNumber}
                    ref={slideRef}
                />
            </div>
            <SlideSettings isActive={isActive} slide={slide} />
        </div>
    );
};
