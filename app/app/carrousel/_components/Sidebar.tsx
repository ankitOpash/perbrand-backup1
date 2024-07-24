import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useContext } from 'react';
import { CarouselContext } from './ContextProvider';
import { Separator } from '@/components/ui/separator';
import { Switch } from '@/components/ui/switch';
import { COLOR_PALETTES } from '../../post-writter/config/const';
import { DownloadButton } from './downloadButton';
import {
    Collapsible,
    CollapsibleContent,
    CollapsibleTrigger,
} from '@/components/ui/collapsible';
import {
    HoverCard,
    HoverCardContent,
    HoverCardTrigger,
} from '@/components/ui/hover-card';
import { Dialog, DialogContent, DialogTrigger } from '@/components/ui/dialog';
import { Slide } from './Slide';
import { range } from '@mantine/hooks';
import {
    Select,
    SelectContent,
    SelectGroup,
    SelectItem,
    SelectLabel,
    SelectTrigger,
    SelectValue,
} from '@/components/ui/select';
import { Button } from '@/components/ui/button';
import { ASPECT_RATIOS_MAP } from './const';

export const CarouselSidebar = () => {
    const {
        carousel: {
            author: { name, handle, pictureUrl },
            settings: {
                alternateColors,
                showCounter,
                showSwipeLabel,
                showAuthor,
                aspectRatio,
            },
        },
        setCarouselAspectRatio,
        toggleAlternateColors,
        editImage,
        editName,
        editHandle,
        toggleShowCounter,
        toggleShowSwipeLabel,
        toggleShowAuthor,
        setColorPalette,
    } = useContext(CarouselContext);

    // TODO: check what this is doing
    // console.log('aspectRatio.valueOf()', aspectRatio.valueOf());
    return (
        <div className='sidebar basis-60 grow border-0 border-green-500 p-4'>
            <div className='flex flex-col gap-2'>
                <div>
                    <h3>Plantilla</h3>
                    <Select
                        value={aspectRatio}
                        defaultValue={aspectRatio}
                        onValueChange={(value) => {
                            setCarouselAspectRatio(value);
                        }}
                    >
                        <SelectTrigger>
                            <SelectValue placeholder='Tamaño' />
                        </SelectTrigger>
                        <SelectContent>
                            <SelectGroup></SelectGroup>
                            <SelectItem value='PORTRAIT' className=''>
                                <div className='flex'>
                                    Linkedin 4:5
                                    <span className='text-[10px] text-green-700 ml-1'>
                                        (Recomendado)
                                    </span>
                                </div>
                            </SelectItem>
                            <SelectItem value='SQUARE' className=''>
                                <div className='flex'>Linkedin 1:1</div>
                            </SelectItem>
                        </SelectContent>
                    </Select>
                    <TemplateSelector />
                </div>
                <Separator />
                <div className='flex gap-2 items-center'>
                    <Label htmlFor='name'>Mostrar autor</Label>
                    <Switch
                        checked={showAuthor}
                        onCheckedChange={toggleShowAuthor}
                    />
                </div>
            </div>
            <Collapsible title='Apariencia'>
                <CollapsibleTrigger>Paleta de colores</CollapsibleTrigger>
                <CollapsibleContent>
                    <ColorPaletteSelect onChange={setColorPalette} />
                </CollapsibleContent>
            </Collapsible>

            <HoverCard openDelay={100}>
                <HoverCardTrigger className='cursor-pointer'>
                    Colores
                </HoverCardTrigger>
                <HoverCardContent>
                    <>
                        <ColorPaletteSelect onChange={setColorPalette} />
                        <div className='flex gap-2 items-center'>
                            <Label htmlFor='name'>Alternar colores</Label>
                            <Switch
                                checked={alternateColors}
                                onCheckedChange={toggleAlternateColors}
                            />
                        </div>
                    </>
                </HoverCardContent>
            </HoverCard>
            <Separator className='mt-2 mb-2' />
            <div className='space-y-4'>
                <div>
                    <h4 className='font-semibold'>Brand kit</h4>
                    <p className='text-primary/50 text-sm'>
                        Lorem ipsum dolor sit amet consectetur adipisicing elit.
                        atque quaerat ab excepturi
                    </p>
                </div>
                <div className=''>
                    <Label htmlFor='name'>Nombre</Label>
                    <Input
                        placeholder='Nombre'
                        id='name'
                        value={name!}
                        onChange={(event) => {
                            editName(event.target.value);
                        }}
                    />
                </div>
                <div className=''>
                    <Label htmlFor='profilePic'>Foto de perfil</Label>
                    <Input
                        placeholder='Nombre'
                        id='profilePic'
                        value={pictureUrl!}
                        onChange={(event) => {
                            editImage(event.target.value);
                        }}
                    />
                </div>
                <div className=''>
                    <Label htmlFor='handle'>Handle</Label>
                    <Input
                        placeholder='Handle'
                        id='handle'
                        value={handle!}
                        onChange={(event) => {
                            editHandle(event.target.value);
                        }}
                    />
                </div>
            </div>
            <DownloadButton />
        </div>
    );
};

type TemplateSelectorProps = {};

const TemplateSelector = ({}: TemplateSelectorProps) => {
    const { currentSlide, carousel, setCurrentSlideTo } =
        useContext(CarouselContext);
    return (
        <Dialog>
            <DialogTrigger className='w-full' asChild>
                <Button className='w-full' variant={'secondary'}>
                    Elige plantilla
                </Button>
            </DialogTrigger>
            <DialogContent className='md:max-w-[80vw] max-w-[calc(100%-1rem)]'>
                <div className='template-rows flex flex-col items-start gap-2 scale-[30%] origin-left'>
                    {/* TODO: This will eventually be images instead */}
                    {range(1, 5).map((index) => {
                        return (
                            <div className='flex' key={index}>
                                {carousel.slides.map((slide, index) => (
                                    <Slide
                                        className=''
                                        key={index}
                                        slide={slide}
                                        slideNumber={index}
                                    />
                                ))}
                            </div>
                        );
                    })}
                </div>
            </DialogContent>
        </Dialog>
    );
};

type ColorPaletteSelectProps = {
    onChange: (colorPalette: TColorPalette) => void;
};

const ColorPaletteSelect = ({ onChange }: ColorPaletteSelectProps) => {
    return (
        <div className='w-full h-full grid grid-cols-3 gap-2'>
            {COLOR_PALETTES.map((palette, index) => (
                <ColorPalette
                    colors={{
                        font: palette.font,
                        background: palette.background,
                        accent: palette.accent,
                    }}
                    key={index}
                    onClick={onChange}
                />
            ))}
        </div>
    );
};

export type TColorPalette = {
    font: string;
    background: string;
    accent: string;
};

type ColorPaletteProps = {
    colors: TColorPalette;
    onClick: (colorPalette: TColorPalette) => void;
};

const ColorPalette = ({
    colors: { font, background, accent },
    onClick,
}: ColorPaletteProps) => {
    const colorClasses = 'w-1/3 h-full border-none outline-none';

    return (
        <div
            className='h-4 border rounded-l-md overflow-hidden rounded-r-md w-full flex'
            onClick={() => onClick({ font, background, accent })}
        >
            <div
                className={colorClasses}
                style={{
                    backgroundColor: font,
                }}
            ></div>
            <div
                className={colorClasses}
                style={{
                    backgroundColor: background,
                }}
            />
            <div
                className={colorClasses}
                style={{
                    backgroundColor: accent,
                }}
            />
        </div>
    );
};
