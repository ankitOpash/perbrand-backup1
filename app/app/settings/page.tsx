'use client';

import { Heading } from '@/components/shared/Heading';
import { Separator } from '@/components/ui/separator';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { AccountSettings } from './_components/AccountSettings';

export default function IdeasPage() {
    return (
        <>
            <Heading
                className='mt-6'
                title='Configuración'
                subtitle='Configura tu espacio de trabajo'
            />
            <Separator />
            <div className='mt-6 space-y-4 2xl:flex gap-8'>
                <Tabs defaultValue='general' className='w-full'>
                    <div className='overflow-x-auto mb-8 '>
                        <TabsList className='flex gap-2 w-fit'>
                            <TabsTrigger value='general'>General</TabsTrigger>
                            <TabsTrigger value='password'>
                                Subscripción
                            </TabsTrigger>
                            <TabsTrigger value='team'>Equipo</TabsTrigger>
                            <TabsTrigger value='ai'>IA</TabsTrigger>
                            <TabsTrigger value='brands'>Tus Marcas</TabsTrigger>
                        </TabsList>
                    </div>
                    <TabsContent value='general'>
                        <AccountSettings />
                    </TabsContent>
                    <TabsContent value='password'></TabsContent>
                    <TabsContent value='team'></TabsContent>
                    <TabsContent value='ai'></TabsContent>
                    <TabsContent value='brands'></TabsContent>
                </Tabs>
            </div>
        </>
    );
}
