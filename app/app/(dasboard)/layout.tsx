import Container from '@/components/shared/container';

type LayoutProps = {
    children: React.ReactNode;
};
export default function DashboardLayout({ children }: LayoutProps) {
    return (
        <Container
            className={
                'flex flex-col border-0 border-red-400 border-dashed grow'
            }
        >
            {children}
        </Container>
    );
}
