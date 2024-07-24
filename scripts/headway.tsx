import {
    Tooltip,
    TooltipContent,
    TooltipProvider,
    TooltipTrigger,
} from '@/components/ui/tooltip';
import { PopoverTrigger } from '@radix-ui/react-popover';
import Script from 'next/script';

export function HeadwayScript() {
    return (
        <>
            <TooltipProvider>
                <Tooltip>
                    <TooltipTrigger asChild>
                        <div className='headway cursor-pointer' id='headway' />
                    </TooltipTrigger>
                    <TooltipContent>
                        <p>Notificaciones</p>
                    </TooltipContent>
                </Tooltip>
            </TooltipProvider>
            <Script
                src='//cdn.headwayapp.co/widget.js'
                strategy='afterInteractive'
            />

            <Script id='updates' strategy='lazyOnload'>{`
            
                    var config = {
                        selector: ".headway",
                        account: "yoawX7",
                        callbacks: {
                        onWidgetReady: function(widget) {
                        },
                        onShowWidget: function(){
                            console.log("Someone opened the widget!");
                        },
                        onShowDetails: function(changelog){
                            console.log(changelog.position); // position in the widget
                            console.log(changelog.id); // unique id
                            console.log(changelog.title); // title
                            console.log(changelog.category); // category, lowercased
                        },
                        onReadMore: function(changelog){
                            console.log(changelog); // same changelog object as in onShowDetails callback
                        },
                        onHideWidget: function(){
                            console.log("Who turned off the light?");
                        }
                        }
                    };

                    Headway.init(config);
            `}</Script>
        </>
    );
}
