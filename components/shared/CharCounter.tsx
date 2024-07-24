import { cn } from '@/lib/utils';

type CharCounterProps = {
    usedChars: number;
    maxChars: number;
};
export function CharCounter({ usedChars, maxChars }: CharCounterProps) {
    const charCounterClasses = cn(
        `absolute bottom-0 right-2 text-xs text-yellow-700/50`,
        usedChars < maxChars && 'text-red-500',
        usedChars > Math.round(maxChars / 2) && 'text-green-500',
        usedChars > maxChars && 'text-destructive'
    );

    const charCounter = `${usedChars} / ${maxChars}`;

    return <p className={charCounterClasses}>{charCounter}</p>;
}
