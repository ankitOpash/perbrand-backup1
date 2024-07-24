import { Separator } from '@/components/ui/separator';
import { Heading } from '@/components/shared/Heading';
import { db } from '@/lib/prisma';

export default async function IdeasPage() {
    const findPostByUserId = async () => {
        return db.linkedinPost.findMany({
            where: {
                author: {
                    is: {
                        name: 'Ricardo Sala',
                    },
                },
            },
        });
    };

    const userPosts = await findPostByUserId();

    return (
        <div>
            <Heading
                className='mt-6'
                title='Genera un post desde cero'
                subtitle='Utiliza el poder de la IA para generar post que tu audiencia no pueda dejar de leer'
            />
            <Separator />
            <div className='mt-6 2xl:flex gap-8 grid grid-cols-4'>
                {userPosts.map((post) => {
                    return (
                        <div
                            key={post.id}
                            className='border border-border p-4 rounded-md'
                        >
                            <p className='line-clamp-2'>{post.content}</p>
                        </div>
                    );
                })}
            </div>
        </div>
    );
}
