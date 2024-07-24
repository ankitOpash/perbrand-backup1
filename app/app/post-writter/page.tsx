import { Heading } from '@/components/shared/Heading';
import { Separator } from '@/components/ui/separator';
import { PostWritterForm } from './_components/PostWritterForm';
import { PostWritterResult } from './_components/GeneratedPost';
import { PostWritterContextProvider } from './_components/PostWritterProvider';

export default function PostWritterPage() {
    return (
        <>
            <Heading
                className='mt-6'
                title='Genera un post desde cero'
                subtitle='Utiliza el poder de la IA para generar post que tu audiencia no pueda dejar de leer'
            />
            <Separator />
            <div className='mt-6 2xl:flex gap-8'>
                <PostWritterContextProvider>
                    <PostWritterForm className='flex-1' />
                    <PostWritterResult className='flex-1' />
                </PostWritterContextProvider>
            </div>
        </>
    );
}
