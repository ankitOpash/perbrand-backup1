'use client';
import { CarouselContextProvider } from './_components/ContextProvider';
import Container from '@/components/shared/container';
import { CarouselSidebar } from './_components/Sidebar';
import { CarouselWorkbench } from './_components/Workbench';
import * as PrismaModels from '@prisma/client';
import { Heading } from '@/components/shared/Heading';

/* TODO: Can we get a better aproach to stretch an element that is inside a flex container without making it this rigid? 
            Right now, it depends on the size of the scrollbar, which is not ideal...
            
            */
const stretchClasses =
    'relative w-[calc(100vw-1rem)] sm:w-[calc(100vw-1rem)] md:w-[calc(100vw-1rem)] lg:w-[calc(100vw-256px-1rem)]';

export default function CarouselPage() {
    return (
        <>
            <Container>
                <Heading
                    className='mt-6 border-0'
                    title='Genera un carrusel'
                    subtitle='Puedes generarlo de forma manual o pedirle a la IA que lo haga por ti a partir de un post'
                />
            </Container>

            <CarouselContextProvider>
                <div
                    className={`flex border-t flex-wrap w-full border-0 border-re-500 grow`}
                >
                    <CarouselSidebar />
                    <CarouselWorkbench />
                </div>
            </CarouselContextProvider>
        </>
    );
}

export type TAspectRatio =
    PrismaModels.AspectRatio[keyof PrismaModels.AspectRatio];

export type TSlide = PrismaModels.Slide;

export type TCarousel = Omit<PrismaModels.Carousel, 'id'>;

// {
//     swipeLabel: string | null;
//     slides: TSlide[];
//     colorPalette: TColorPalette;
//     fontPalette: TFontPalette;
//     backgroundPattern: string | null;
//     authorName: string | null;
//     authorPictureUrl: string | null;
//     authorHandle: string | null;
//     settings: {
//         alternateColors: boolean;
//         showCounter: boolean;
//         showSwipeLabel: boolean;
//         showAuthor: boolean;
//         aspectRatio: TAspectRatio;
//     };
// };

export type TColorPalette = PrismaModels.ColorPalette;

export type TFontPalette = PrismaModels.FontPalette;
