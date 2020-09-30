/*
 *   Copyright 2020 Leon Latsch
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

package dev.leonlatsch.photok.ui.process

import android.app.Application
import androidx.hilt.lifecycle.ViewModelInject
import androidx.lifecycle.viewModelScope
import dev.leonlatsch.photok.model.database.entity.Photo
import dev.leonlatsch.photok.model.repositories.PhotoRepository
import dev.leonlatsch.photok.ui.process.base.BaseProcessViewModel
import dev.leonlatsch.photok.ui.process.base.ProcessState
import kotlinx.coroutines.launch

/**
 * ViewModel for deleting multiple photos.
 *
 * @since 1.0.0
 * @author Leon Latsch
 */
class DeleteViewModel @ViewModelInject constructor(
    private val app: Application,
    private val photoRepository: PhotoRepository
) : BaseProcessViewModel() {

    lateinit var photos: List<Photo>

    override fun process() = viewModelScope.launch {
        var current = 1
        processState.postValue(ProcessState.PROCESSING)
        progress.value?.update(current, photos.size)

        for (photo in photos) {
            if (processState.value == ProcessState.ABORTED) {
                return@launch
            }

            // Delete image
            delete(photo)
            progress.value?.update(current, photos.size)
            current++
        }

        processState.postValue(ProcessState.FINISHED)
    }

    private suspend fun delete(photo: Photo) {
        if (photo.id == null) {
            failuresOccurred = true
            return
        }

        val success = photoRepository.deletePhotoAndData(app, photo)
        if (!success) {
            failuresOccurred = true
        }
    }

}