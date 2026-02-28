import { StudioAdapterInput, StudioAdapterResult, StudioLaunchModel } from '../../../types/studio';
export interface StudioModelAdapter {
    readonly model: StudioLaunchModel;
    run(input: StudioAdapterInput): Promise<StudioAdapterResult>;
}
//# sourceMappingURL=adapterTypes.d.ts.map