import {
    Popover,
    PopoverContent,
    PopoverTrigger,
} from '@/components/ui/popover';
import {
    Tooltip,
    TooltipContent,
    TooltipProvider,
    TooltipTrigger,
} from '@/components/ui/tooltip';
import { Badge, Link } from 'lucide-react';

type Notification = {
    type: 'éxito' | 'error' | 'aviso' | 'info' | 'nuevo' | 'mejora';
    title: string;
    description: string;
    href: string;
};

type NotificationMenuProps = {
    notifications: Notification[];
};

//BOILER: This could work but they use https://headwayapp.co/
export const NotificationMenu = ({}: NotificationMenuProps) => {
    return (
        <Popover>
            <TooltipProvider>
                <Tooltip>
                    <TooltipTrigger asChild>
                        <PopoverTrigger asChild className='cursor-pointer'>
                            <div className='flex items-center justify-center h-2 w-2 rounded-full bg-primary animate-pulse' />
                        </PopoverTrigger>
                    </TooltipTrigger>
                    <TooltipContent>
                        <p>Notificaciones</p>
                    </TooltipContent>
                </Tooltip>
            </TooltipProvider>
            <PopoverContent className='p-0'>
                {FAKE_NOTIFICATIONS.map((notification) => (
                    <NotificationCard
                        notification={notification}
                        key={notification.description}
                    />
                ))}
            </PopoverContent>
        </Popover>
    );
};

export const NotificationCard = ({
    notification,
}: {
    notification: Notification;
}) => {
    const { type, title, description, href } = notification;
    const bagdeColor = {
        éxito: 'bg-green-100 border-green-600 text-green-600',
        error: 'bg-red-100 border-red-600 text-red-600',
        aviso: 'bg-yellow-100 border-yellow-600 text-yellow-600',
        info: 'bg-blue-200 border-blue-600 text-blue-600',
        nuevo: 'bg-indigo-200 border-indigo-600 text-indigo-600',
        mejora: 'bg-green-200 border-green-600 text-green-600',
    }[type];

    return (
        <>
            <div
                className='flex items-center gap-2 cursor-pointer
            hover:bg-primary/5
            group
            p-2
            py-4
            '
            >
                <div className='text-xs'>
                    <Badge className={` ${bagdeColor} mr-2`}>
                        {notification.type}
                    </Badge>
                    <Link
                        href={notification.href}
                        className='font-semibold group-hover:underline inline-block mr-4'
                    >
                        {title}
                    </Link>
                    <p className='text-primary/40 inline'>{description}</p>
                </div>
            </div>
        </>
    );
};

const FAKE_NOTIFICATIONS: Notification[] = [
    {
        type: 'éxito',
        title: '¡Bienvenido!',
        description:
            'Lorem ipsum dolor sit amet consectetur adipisicing elit. Quisquam, voluptatibus.',
        href: '/',
    },
    {
        type: 'error',
        title: 'Error al crear el post',
        description:
            'Lorem ipsum dolor sit amet consectetur adipisicing elit. Quisquam, voluptatibus.',
        href: '/',
    },
    {
        type: 'aviso',
        title: '¡Bienvenido!',
        description:
            'Lorem ipsum dolor sit amet consectetur adipisicing elit. Quisquam, voluptatibus.',
        href: '/',
    },
    {
        type: 'info',
        title: '¡Bienvenido!',
        description:
            'Lorem ipsum dolor sit amet consectetur adipisicing elit. Quisquam, voluptatibus.',
        href: '/',
    },
    {
        type: 'nuevo',
        title: '¡Bienvenido!',
        description:
            'Lorem ipsum dolor sit amet consectetur adipisicing elit. Quisquam, voluptatibus.',
        href: '/',
    },
    {
        type: 'mejora',
        title: '¡Bienvenido!',
        description:
            'Lorem ipsum dolor sit amet consectetur adipisicing elit. Quisquam, voluptatibus.',
        href: '/',
    },
];
