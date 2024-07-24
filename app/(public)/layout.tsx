import Container from '@/components/shared/container';
import Navbar from '@/components/shared/navbar/Navbar';

export default function DefaultLayout({
    children,
}: {
    children: React.ReactNode;
}) {
    return (
        <div className='flex h-[100dvh] overflow-hidden'>
            {/* Sidebar */}
            {/* <Sidebar /> */}

            {/* Content area */}
            <div className='relative flex flex-col flex-1 overflow-y-auto overflow-x-hidden'>
                {/*  Site header */}
                <Navbar />

                <main className='gap flex flex-1 flex-col py-12 [&>*:first-child]:scroll-mt-16'>
                    <Container className={''}>{children}</Container>
                </main>
            </div>
        </div>
    );
}
