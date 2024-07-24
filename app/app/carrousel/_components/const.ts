import { TCarousel, TSlide } from '@/app/app/carrousel/page';
import * as PrismaClient from '@prisma/client';

export const fakeSlides: TSlide[] = [
    {
        image: {
            url: '/images/placeholders/user.png',
        },
        paragraphs: [
            {
                content:
                    'Loremi ipsum dolor sit amet consectetur adipisicing elit. Quisquam, voluptatum.',
                isShown: true,
            },
        ],
        title: {
            content: 'some randum title',
            isShown: true,
        },
        // Ignored for now
        settings: {
            colorPalette: {
                background: '',
                font: '',
                accent: '',
            },
            fontPalette: {
                primary: '',
                secondary: '',
                handWriting: '',
            },
        },
        tagline: {
            content: 'some randum tagline',
            isShown: true,
        },
    },
];

export const fakeCarousel: TCarousel = {
    slides: fakeSlides,
    author: {
        handle: '@ricSala',
        name: 'Ricardo Sala',
        pictureUrl: '/images/placeholders/user.png',
    },
    swipeLabel: 'Desliza',
    settings: {
        colorPalette: {
            background: '#000000',
            font: '#ffffff',
            accent: '#ffffff',
        },
        fontPalette: {
            primary: 'Roboto',
            secondary: 'Roboto',
            handWriting: 'Roboto',
        },
        aspectRatio: 'PORTRAIT',
        backgroundPattern: null,
        alternateColors: false,
        showAuthor: true,
        showCounter: true,
        showSwipeLabel: true,
    },
};

// REVIEW: This took a while!!!!
export const ASPECT_RATIOS_MAP = {
    PORTRAIT: '4:5',
    SQUARE: '1:1',
} as const satisfies Record<PrismaClient.AspectRatio, string>;
// REVIEW THIS!
// as const made the strings literal types instead of just string
// satisfies makes sure the keys are the same as the enum from the prisma schema

type TAspectRatioMap = typeof ASPECT_RATIOS_MAP;
export type TAspectRatioEnum = keyof TAspectRatioMap;
export type TAspectRatioLabel = TAspectRatioMap[TAspectRatioEnum];

// export type TAspectRatioLabel = TAspectRatioMap[TAspectRatioEnum];
