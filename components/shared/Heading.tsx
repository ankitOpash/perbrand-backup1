import { cn } from '@/lib/utils';

type CardHeaderProps = {
    title: string;
    subtitle?: string;
    className?: string;
};

export const Heading = ({ title, subtitle, className }: CardHeaderProps) => {
    return (
        <div className={cn(`mb-6 bg-background`, className)}>
            <h1 className={`text-3xl text-primary font-bold `}>{title}</h1>
            <p>{subtitle}</p>
        </div>
    );
};
