import { StudioAdapterInput, StudioAdapterResult } from '../../../types/studio';
import { StudioModelAdapter } from './adapterTypes';
export declare class AnimateDiffAdapter implements StudioModelAdapter {
    readonly model: "animatediff";
    run(input: StudioAdapterInput): Promise<StudioAdapterResult>;
}
//# sourceMappingURL=animateDiffAdapter.d.ts.map