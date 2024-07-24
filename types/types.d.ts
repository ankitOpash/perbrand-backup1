import { ASPECT_RATIOS } from '@/app/app/post-writter/config/const';
import type { AspectRatio, Prisma, PrismaClient } from '@prisma/client';

export type HttpStatusCode = 200 | 201 | 400 | 401 | 404 | 500; // Extend as needed

export type PaginationInfo = {
    currentPage: number;
    totalPages: number;
    pageSize: number;
    totalItems: number;
};

//   Utility type: Make a specific property nullable
export type MakeNullable<T, K extends keyof T> = Omit<T, K> & // First we ommit the whole property
    Partial<Pick<T, K>>; // Then we add it as a partial property

export type ChildrenProps = {
    children: React.ReactNode;
};

export type AuthContextProps = {
    isLoggedIn: Boolean;
    user: any; // TODO: temporal
};

export type Post = {
    slug: string;
    title: string;
    published: boolean;
    tags: string[];
    date: string;
};

export type ApiResponse<T = undefined, E = ApiError> =
    | {
          statusCode: HttpStatusCode;
          message: string;
          data: T | undefined;
          ok: true;
          meta?: any; // Additional metadata
          pagination?: PaginationInfo;
      }
    | {
          statusCode: HttpStatusCode;
          message: string;
          ok: false;
          error: E;
          meta?: any; // Additional metadata
      };

export type ApiRequestBody<
    T = undefined,
    A = 'CREATE' | 'UPDATE' | 'DELETE' | 'INVITE' | 'EXIT',
> = {
    data: T;
    action: A;
};

export type TStatus = 'idle' | 'loading' | 'success' | 'error';

export type TCarouselTemplate = {};

export type TSlideContent = {
    title: string;
    paragraph: string;
    tagline: string;
};

// #### START OF TRYING
// REVIEW: Not sure if this makes things easier or more complicated...will take it for a spin
// IMPORTANT: NOT USING IT, BUT MAY BE USEFUL IN THE FUTURE
type ModelNames = Prisma.ModelName; // Union Type with the names of all Models: "User" | "Post"...

// Prisma model is a Record...
export type PrismaModels = {
    // ...where each key is a ModelName...
    [M in ModelNames]: Exclude<
        // ...and each value is the awaited return type of the findUnique method of the PrismaClient of the corresponding model
        Awaited<ReturnType<PrismaClient[Uncapitalize<M>]['findUnique']>>,
        null //..excluding null
    >;
};
// Is the equivalent of doing something like this:
// const user = await prisma.user.findUnique({ where: { id: 1 } });
// typeof user
// #### END OF TRYING

// Helper type that converts a database model into an object to work with in the frontend (i.e. ommits id, createdAt, updatedAt, etc).
export type Pure<T> = Omit<T, 'createdAt' | 'updatedAt'>;
