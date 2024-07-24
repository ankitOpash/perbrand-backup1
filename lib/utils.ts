import {
    POST_CATEGORIES,
    VOICE_TONES,
} from '@/app/app/post-writter/config/const';
import { POST_TEMPLATES } from '@/app/app/post-writter/config/prompts';
import { Pure } from '@/types/types';
import * as PrismaClient from '@prisma/client';
import { type ClassValue, clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
    return twMerge(clsx(inputs));
}

export const verboseLog = (message: string, ...optionalParams: any[]) => {
    if (process.env.NODE_ENV === 'development') {
        console.log(message, optionalParams);
    }
};

export const wait = async (ms: number) =>
    new Promise((resolve) => setTimeout(resolve, ms));

export const range = (start: number, end: number, step = 1) => {
    let output = [];

    if (typeof end === 'undefined') {
        end = start;
        start = 0;
    }

    for (let i = start; i < end; i += step) {
        output.push(i);
    }

    return output;
};

/**
 * Debounce function. When we call this function, it will return a new function that will have a timeout (closure). If the timeout is already set, it will clear it and set a new one, creating a "debounce" effect. The function has access to the timeout variable because of the closure: it was in its scope when the function was created.
 */
export function debouncedFunction<T extends (...args: any[]) => any>(
    func: T,
    waitFor: number
) {
    // This variable will hold the reference to the timeout
    let timeout: NodeJS.Timeout;

    // Return a new function that will debounce the execution of 'func'
    return (...args: Parameters<T>) => {
        // If 'timeout' is already set, clear it. This happens if the debounced
        // function is called again before the timeout has elapsed
        if (timeout) {
            clearTimeout(timeout);
        } else {
        }
        // create a new timeout
        timeout = setTimeout(() => {
            func(...args);
        }, waitFor);
    };
}

export const deepCopy = <T>(obj: T) => {
    return JSON.parse(JSON.stringify(obj)) as T;
};

export function isEven(n: number) {
    return n % 2 == 0;
}

export const getPostTemplateById = (id: string) => {
    const template = POST_TEMPLATES.find((template) => template.id === id);

    if (!template) {
        throw new Error(`Template with id ${id} not found`);
    }

    return template;
};

export const getAllPostTemplates = () => {
    const template = POST_TEMPLATES;

    return template;
};

export const getAllPostCategories = () => {
    const categories = POST_CATEGORIES;

    return categories;
};

export const getVoiceToneById = (id: number) => {
    const tone = VOICE_TONES.find((tone) => tone.id === id);

    if (!tone) {
        throw new Error(`Tone with id ${id} not found`);
    }

    return tone;
};

export const capitalizeFirstLetter = (string: string) => {
    return string.charAt(0).toUpperCase() + string.slice(1);
};

export const uploadFileToCloudinary = async (file: File) => {};
