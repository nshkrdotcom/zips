# KEM_rsp_to_zig.py
import re
import os
import zipfile
import zlib

def parse_kat_file(filepath, num_vectors=None):
    """Parses KAT .rsp file, handling various formatting issues."""
    vectors = []
    ctr = 0;
    with open(filepath, 'r', encoding='utf-8') as f:
        while True:
            # if (ctr % 100) == 0: print(str(ctr) + "len vectors " + str(len(vectors)) + " num vectrors:"+str(num_vectors))
            ctr += 1
            if num_vectors is not None and len(vectors) >= num_vectors:
                break
            vector = {}
            while True:
                line = f.readline()
                if not line:
                    break
                line = line.strip()
                match = re.match(r"^(pk|sk|ct|ss) = (.+)", line)                
                if match:
                    field = line[0:2]
                    hex_str = match.group(2).strip()
                    try:
                        vector[field] = bytes.fromhex(hex_str)
                        if len(vector) == 4:
                            vectors.append(vector)
                            vector = {}
                            break
                    except ValueError:
                        print(f"Warning: Invalid hex '{hex_str}' for '{field}' in '{filepath}'. Skipping vector.")
                        print(f"Problematic line: '{line}'")
                        vector = {}
    return vectors

def generate_zig_file(vectors, filename, compress=False, security_level="512"):
    """Generates a Zig file containing the test vectors."""

    zig_code = f"""pub const kat_vectors_{security_level} = [_]struct {{
    pk: []const u8,
    sk: []const u8,
    ct: []const u8,
    ss: []const u8,
}} {{
"""
    for vector in vectors:
        zig_code += f"""    .{{
        .pk = &[_]u8{{{', '.join(map(hex, vector['pk']))}}},
        .sk = &[_]u8{{{', '.join(map(hex, vector['sk']))}}},
        .ct = &[_]u8{{{', '.join(map(hex, vector['ct']))}}},
        .ss = &[_]u8{{{', '.join(map(hex, vector['ss']))}}},
    }},
"""
    zig_code += "};\n"
    data_to_write = zig_code.encode('utf-8')
    directory = "vectors"
    if not os.path.exists(directory):
        os.makedirs(directory)
    with open(directory + '/' + filename, "wb") as f:
        f.write(data_to_write)

def main():
    kat_dir = "../../post-quantum-cryptography/KAT/MLKEM"
    num_vectors_per_set = 1
    num_failure_vectors = 1
    for security_level in ["512", "768", "1024"]:
        kat_filepath = os.path.join(kat_dir, f"kat_MLKEM_{security_level}.rsp")
        # Small set of vectors
        print(f"Parsing input file: " + kat_filepath + ", " + str(num_vectors_per_set) + " vectors per set")
        small_vectors = parse_kat_file(kat_filepath, num_vectors_per_set)
        small_output_filename = f"kat_vectors_{security_level}_small.zig"
        print(f"Generating small output zig file: " + small_output_filename)
        generate_zig_file(small_vectors, small_output_filename, compress=False, security_level=security_level)
        
        # All vectors (for compressed archive) + failure vectors
        ## print(f"Parsing full output file: " + kat_filepath + " (all vectors)")
        ## all_vectors = parse_kat_file(kat_filepath) # without num_vectors specified, parses all
        ## all_output_filepath = f"kat_vectors_{security_level}_all.zig"

if __name__ == "__main__":
    main()