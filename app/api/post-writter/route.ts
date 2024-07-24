import { NextRequest, NextResponse } from 'next/server';
import bcrypt from 'bcryptjs';
import { ApiRequestBody, ApiResponse } from '@/types/types';
import { register } from '@/lib/register-user';
import { User } from '@prisma/client';
import { RegisterFormValues } from '@/schemas/auth-schemas';
import { getPostTemplateById, getVoiceToneById, wait } from '@/lib/utils';
import {
    CustomFormSchema,
    PostRequest,
} from '@/app/app/post-writter/_components/PostWritterForm';
import { z } from 'zod';
import { ChatOpenAI } from '@langchain/openai';
import { StreamingTextResponse } from 'ai';
import { HttpResponseOutputParser } from 'langchain/output_parsers';
import { PromptTemplate } from '@langchain/core/prompts';
import {
    generalInstructions,
    writterPrompt,
} from '@/app/app/post-writter/config/prompts';

export async function POST(req: NextRequest) {
    try {
        const body = await req.json();
        const { action }: { action: RouteActions } = body;

        switch (action) {
            case 'WRITE':
                const {
                    data: { description, templateId, toneId },
                }: WritterReq<'WRITE'> = body;

                if (
                    description === 'string' ||
                    typeof templateId !== 'string' ||
                    typeof toneId !== 'number'
                ) {
                    console.log(description, templateId, toneId);
                    console.log('MISSING_DATA');
                    return NextResponse.json(
                        { error: 'Datos incorrectos, prueba de nuevo' },
                        { status: 400 }
                    );
                }

                const model = new ChatOpenAI({
                    temperature: 0.8,
                    modelName: 'gpt-4-0613',
                    streaming: true,
                    callbacks: [
                        {
                            handleLLMNewToken(token) {
                                // console.log(token);
                            },
                        },
                    ],
                });

                const promptTemplate = PromptTemplate.fromTemplate(
                    `
                    Escribe el mejor post de linkedin que puedas siguiendo esta plantilla o ejemplo pero en un tono {tone}:

                    ___PLANTILLA-O-EJEMPLO___
                    {example}.
                    ___END_PLANTILLA-O-EJEMPLO___

                    
                    __INSTRUCTIONS__
                    Only return the post text, no intro, not outro, no ###.


                    Keep the line breaks, emojis, bold, italic, etc. they are important

                    The text between curly braces is a placeholder, DO NOT INCLUDE IT. Replace it with the content that makes sense.

                    Puedes modificar la plantilla para que tu post sea {tone}. No la sigas al pie de la letra.

                    Las frases entre <> deben ser MUY POCO modificadas. Procura matenerlas tal cual.
                    __END_INSTRUCTIONS__

                    __USER_PROMPT__
                          
                    Apply the template to this content (complete what necesary): 
                    {userPrompt}.
                    ___END_USER_PROMPT___
                    `
                    // `${writterPrompt} ${getPostTemplateById(templateId).content} ${promptEnd}`
                );

                // Este es un post que ha funcionado muy muy bien en linkedin:

                //     ___PLANTILLA___
                //     Most people suck at boosting ecommerce conversion rates.

                //         But if you avoid these 5 common mistakes, I guarantee you won’t.

                //         Ignoring Customer Feedback 🔁
                //         → Not utilizing customer insights effectively.

                //         Do this instead
                //         ↳ Regularly gather and analyze customer feedback.
                //         ↳ Implement changes based on consistent customer pain points.

                //         Poor Website Navigation ⛵
                //         → Complicated, unclear user journey.

                //         Do this instead
                //         ↳ Streamline site structure for easy navigation.
                //         ↳ Ensure clear, concise menus and call-to-action buttons.

                //         Neglecting Mobile Users 📱
                //         → Website not optimized for mobile.

                //         Do this instead
                //         ↳ Optimize website for mobile responsiveness.
                //         ↳ Test regularly on different devices and browsers.

                //         Underestimating Product Descriptions 💬
                //         → Vague, uninformative product details.

                //         Do this instead
                //         ↳ Provide detailed, compelling product descriptions.
                //         ↳ Include high-quality images and videos.

                //         Ignoring Checkout Optimization 💳
                //         → Long, complicated checkout process.

                //         Do this instead
                //         ↳ Simplify the checkout process, reduce steps.
                //         ↳ Offer multiple payment options and guest checkout.

                //         A 2% conversion rate might seem okay, but it's far from the ceiling. Small tweaks in approach, focusing on customer experience, and optimizing your website can significantly boost your conversion rates.

                //         Start implementing these changes today, and watch your ecommerce store thrive. Remember, it's not just about driving traffic, but converting that traffic effectively. Raise your standards, and aim for conversion rates that truly reflect your store's potential!.
                //     ___END_PLANTILLA___

                //     __INSTRUCTIONS__
                //     Quiero que escribas un post que utilice las mismas ténicas de copywritting y estructura, pero que hable de {userPrompt}.

                //     Además, tu post debe estar list para compartir (formato, emojis, etc), y estar escrito en un tono muy {tone} y escrito en español localizado en España.
                const outputParser = new HttpResponseOutputParser({});

                // We create a chain that pipes our prompt template into the model, and then the model into the output parser
                const chain = promptTemplate.pipe(model).pipe(outputParser);

                // We start the chain as a stream
                const stream = await chain.stream({
                    example: getPostTemplateById(templateId).content,
                    instructions: generalInstructions,
                    userPrompt: description,
                    tone: getVoiceToneById(toneId).name,
                });

                // TODO: use this instead so you learn about streams: https://michaelangelo.io/blog/server-sent-events
                return new StreamingTextResponse(stream);
        }
    } catch (error) {
        console.log(error, 'REGISTRATION_ERROR');
        return NextResponse.json(
            { error: 'Something went wrong' },
            { status: 500 }
        );
    }
}

type RouteApiMap = {
    WRITE: {
        reqData: PostRequest;
        resData: string;
    };
    // UPDATE: {
    //     reqData: StudioFormValues;
    //     resData: Studio;
    // };
};

type RouteActions = keyof RouteApiMap;

export type WritterRes<A extends RouteActions> = // Generic type whose value is one of the actions
    ApiResponse<RouteApiMap[A]['resData']>;

export type WritterReq<A extends RouteActions> = // Generic type whose value is one of the actions
    ApiRequestBody<RouteApiMap[A]['reqData'], A>;
