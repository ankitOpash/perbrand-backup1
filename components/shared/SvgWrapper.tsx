import { ReactNode } from 'react';

type QuadPatternProps = {
    primaryColor?: string;
    secondaryColor?: string;
    opacity?: number;
    children: ReactNode;
};

export const SvgWrapper = ({
    primaryColor,
    secondaryColor,
    opacity = 0.3,
    children,
}: QuadPatternProps) => {
    return (
        <svg
            className='h-full w-full'
            xmlns='http://www.w3.org/2000/svg'
            version='1.1'
            viewBox='0 0 640 800'
            id='qqquad'
            opacity={opacity}
            stroke={secondaryColor}
        >
            {children}
        </svg>
    );
};
