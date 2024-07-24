'use client';

import { cn } from '@/lib/utils';
import { CSSProperties, useEffect, useId, useRef, useState } from 'react';

// Credit where credit is due: https://codepen.io/feketegy/pen/RwGBgyq

type ContentEditableProps = {
    htmlElement: 'p' | 'div' | 'h1' | 'h2' | 'h3' | 'h4' | 'h5';
    className?: string;
    onChange: (value: string) => void;
    value: string;
    style?: CSSProperties | undefined;
    children?: React.ReactNode;
};

const allowedHtmlElements = {
    p: 'p',
    div: 'div',
    h1: 'h1',
    h2: 'h2',
    h3: 'h3',
    h4: 'h4',
    h5: 'h5',
} as const;

function getCaret(el: HTMLElement) {
    let caretAt = 0;
    // .getSelection() returns a Selection object representing the range of text selected by the user or the current position of the caret. It's not the same as .activeElement
    const sel = window.getSelection();

    // If there is no selection, return the caret position
    if (!sel) {
        return caretAt;
    }

    // Does the caret count as a range?
    if (sel.rangeCount == 0) {
        return caretAt;
    }

    const range = sel.getRangeAt(0);
    const preRange = range.cloneRange();
    preRange.selectNodeContents(el);
    preRange.setEnd(range.endContainer, range.endOffset);
    caretAt = preRange.toString().length;

    return caretAt;
}

function setCaret(el: HTMLElement, offset: number) {
    let sel = window.getSelection();
    let range = document.createRange();

    if (!sel) {
        return;
    }

    if (el.childNodes.length == 0) {
        el.appendChild(document.createTextNode(''));
    }

    // @ts-ignore
    if (offset > el.childNodes[0].length || offset < 0) {
        offset = 0;
    }

    range.setStart(el.childNodes[0], offset);
    range.collapse(true);
    sel.removeAllRanges();
    sel.addRange(range);
}

export function CustomContentEditable({
    htmlElement,
    className,
    onChange,
    value,
    style,
    children,

    ...props
}: ContentEditableProps) {
    const editableElementref = useRef<HTMLParagraphElement>(null);
    const caretPosition = useRef<number>(0);

    const Element = allowedHtmlElements[htmlElement];
    // get if the element is focused
    const id = useId();

    useEffect(() => {
        if (editableElementref.current) {
            setCaret(editableElementref.current, caretPosition.current);
            editableElementref.current.focus();
        }
    }, [value]);

    return (
        <Element
            className={cn(``, className)}
            ref={editableElementref}
            suppressContentEditableWarning
            contentEditable={true}
            style={{
                ...style,
            }}
            onInput={(event) => {
                if (!editableElementref.current) return;
                caretPosition.current = getCaret(editableElementref.current);
                // @ts-ignore
                onChange(event.target.innerText);
            }}
            onPaste={() => {
                caretPosition.current = 0;
            }}
            {...props}
            id={id}
        >
            {value}
        </Element>
    );
}
