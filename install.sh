#!/bin/bash
# Install the DPT wireshark dissector

# Possible init.lua file locations
known_init_locations=(/Applications/Wireshark.app/Contents/Resources/share/wireshark/init.lua /etc/wireshark/init.lua)
init_file=""

# Error messages
more_work="Manual work needed to complete installation."
dissector_needed="The lua files in the git repository need to be copied to the user's wireshark directory."
init_file_needed="The init.lua file used by wireshark to setup the Lua environment must load the dpt.lua file from the user's wireshark directory."

# Install the dissector into the user directory
function install_dissector {
    # Clean up existing files and copy new ones
    rm -f ~/.wireshark/dpt*.lua && cp ./dpt*.lua ~/.wireshark

    if [ $? -eq 1 ]; then
        echo "Failed to install the dissector into the user's wireshark directory."
        echo ${more_work}
        echo ${dissector_needed}
        echo ${init_file_needed}
        exit 1
    fi
}

# Locate the init.lua file and set the init_file variable
function find_init_file {
    for file in ${known_init_locations[@]}; do
        if [ -f ${file} ]; then
            init_file=${file}
            return
        fi
    done

    echo "Failed to find init.lua file."
    echo ${more_work}
    echo ${init_file_needed}
    exit 1
}

# Updates the file indicated by the init_file variable to load the dissector
function update_init_file {
    grep dpt.lua ${init_file} > /dev/null
    if [ $? -eq 1 ]; then
        if [ -w ${init_file} ]; then
            echo '\ndofile(USER_DIR.."dpt.lua")\n' >> ${init_file}
        else
            echo "File ${init_file} not writable, attempting to update with sudo."
            sudo sh -c "echo '\ndofile(USER_DIR..\"dpt.lua\")\n' >> /etc/wireshark/init.lua"
        fi

        if [ $? -eq 1 ]; then
            echo "Failed to update file ${init_file}."
            echo ${more_work}
            echo ${init_file_needed}
            exit 1
        fi
    fi
}

# Go through the install steps
install_dissector
find_init_file
update_init_file
echo "Install complete"
exit 0

